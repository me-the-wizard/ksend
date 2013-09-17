#include <linux/err.h>
#include <linux/if_ether.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/string.h>

#include <net/net_namespace.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Merlin Davis <me.the.wizard@gmail.com>");

static char* iface = "eth0";
module_param(iface, charp, 0);
MODULE_PARM_DESC(iface, "Name of output interface");

static unsigned long n = 0;
module_param(n, ulong, 0);
MODULE_PARM_DESC(n, "Number of packets to send (zero for continuous)");


static const unsigned int MAX_PENDING = 10u;

static struct net_device* sendDev = NULL;
static struct task_struct* sendThread = NULL;
static unsigned long nSent = 0uL;
static atomic_t nPending;
static wait_queue_head_t sendWq;

// Real ICMP echo response frame captured from eth0
static char FRAME_DATA[] =
   {
      0x0a, 0x00, 0x27, 0x00, 0x00, 0x00,              // dest MAC addr
      0x08, 0x00, 0x27, 0x98, 0xa0, 0xea,              // src MAC addr
      0x08, 0x00,                                      // IPv4

      0x45,                                            // v4, header length 20
      0x00,                                            // DCSP, ECN
      0x00, 0x54,                                      // total IPv4 length 84
      0xdc, 0x5a,                                      // ID
      0x00, 0x00,                                      // flags, fragment offset
      0x40,                                            // TTL 64
      0x01,                                            // protocol ICMP
      0xac, 0xf2,                                      // IPv4 header checksum
      0xc0, 0xa8, 0x38, 0x0a,                          // src IP addr
      0xc0, 0xa8, 0x38, 0x01,                          // dest IP addr

      0x00,                                            // echo reply
      0x00,                                            // code 0
      0xf8, 0x17,                                      // ICMP header checksum
      0x07, 0x80,                                      // echo ID
      0x00, 0x0a,                                      // echo sequence number

      0x94, 0x89, 0x16, 0x52, 0x00, 0x00, 0x00, 0x00,  // echo data
      0x8d, 0xaf, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
      0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
      0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37
   };


static void testSend_exit(void);
static int testSendThreadfn(void* data);
static void testSend_skb_destruct(struct sk_buff* skb);


static int __init testSend_init(void)
{
   struct net* netNs = NULL;
   int err = 0;

   atomic_set(&nPending, 0);
   init_waitqueue_head(&sendWq);

   if (!iface)
   {
      printk(KERN_ERR "test_send: Non-null device name must be specified "
                      "via iface=<name>\n");
      err = -EINVAL;
      goto err;
   }

   rcu_read_lock();
   for_each_net_rcu(netNs)
   {
      sendDev = dev_get_by_name(netNs, iface);
      if (sendDev)
      {
         break;
      }
   }
   netNs = NULL;
   rcu_read_unlock();

   if (!sendDev)
   {
      printk(KERN_ERR "Invalid device name '%s'\n", iface);
      err = -EINVAL;
      goto err;
   }

   sendThread = kthread_run(testSendThreadfn, 0, "test_send");
   if (IS_ERR(sendThread))
   {
      err = PTR_ERR(sendThread);
      sendThread = NULL;
      goto err;
   }
   // keep reference so we can kthread_stop() even after thread returns
   get_task_struct(sendThread);

   return 0;

err:
   testSend_exit();
   return err;
}
module_init(testSend_init);


static void testSend_exit(void)
{
   if (sendThread)
   {
      kthread_stop(sendThread);
      // cleanup extra reference kept for the kthread_stop()
      put_task_struct(sendThread);
      sendThread = NULL;
   }

   while (atomic_read(&nPending) > 0)
   {
      wait_event_interruptible(sendWq, atomic_read(&nPending) <= 0);
   }

   if (sendDev)
   {
      dev_put(sendDev);
      sendDev = NULL;
   }
}
static void __exit _testSend_exit(void)
{
   testSend_exit();
   printk(KERN_INFO "test_send: Sent %lu frames\n", nSent);
}
module_exit(_testSend_exit);


static int testSendThreadfn(void* data)
{
   int reservedSpace = max((int)LL_RESERVED_SPACE(sendDev),
                           (int)sizeof(struct ethhdr));
   int buffLen = reservedSpace - sizeof(struct ethhdr) +
                 sizeof(FRAME_DATA) +
                 sendDev->needed_tailroom;

   while (!kthread_should_stop() && (n == 0 || nSent < n))
   {
      struct sk_buff* skb = NULL;
      int err = 0;

      while (atomic_read(&nPending) >= MAX_PENDING)
      {
         wait_event_interruptible(sendWq, atomic_read(&nPending) < MAX_PENDING);
         if (kthread_should_stop())
         {
            goto out;
         }
      }

      skb = alloc_skb(buffLen, GFP_KERNEL);
      if (!skb)
      {
         printk(KERN_ERR "test_send: Couldn't allocate SKB\n");
         schedule();
         continue;
      }

      skb_reserve(skb, reservedSpace);
      skb_reset_network_header(skb);
      skb_put(skb, sizeof(FRAME_DATA) - sizeof(struct ethhdr));
      skb_push(skb, sizeof(struct ethhdr));
      skb_reset_mac_header(skb);
      skb_reset_mac_len(skb);
      err = skb_store_bits(skb, 0, FRAME_DATA, sizeof(FRAME_DATA));
      if (err)
      {
         printk(KERN_ERR "test_send: Error %d storing to SKB\n", err);
         schedule();
         continue;
      }

      skb->dev = sendDev;
      skb->protocol = htons(ETH_P_IP);
      skb->destructor = testSend_skb_destruct;
      skb_shinfo(skb)->destructor_arg = NULL;

      // NOTE: Without this, the destructor is called twice and there is an
      //    almost immediate kernel panic.  With it, a kernel panic still
      //    occurs but takes a while to manifest.
      skb_get(skb);

      atomic_inc(&nPending);
      err = net_xmit_eval(dev_queue_xmit(skb));
      if (err)
      {
         printk(KERN_ERR "test_send: Error %d sending frame\n", err);
         schedule();
         continue;
      }

      ++nSent;

      //printk(KERN_ERR "test_send: SENT SKB\n");
   }
out:

   return 0;
}

static void testSend_skb_destruct(struct sk_buff* skb)
{
   //printk(KERN_ERR "test_send: DESTRUCTING SKB\n");
   atomic_dec(&nPending);
   wake_up_all(&sendWq);
}
