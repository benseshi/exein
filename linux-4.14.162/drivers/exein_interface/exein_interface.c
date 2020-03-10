/* Copyright 2019 Exein. All Rights Reserved.

Licensed under the GNU General Public License, Version 3.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.gnu.org/licenses/gpl-3.0.html

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
==============================================================================*/

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>


#define NETLINK_USER 31
//#define EXEIN_PRINT_DEBUG
#define BUFFLEN 768
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Exein");

extern int exein_debug;
extern void *exein_payload_process_ptr;
extern void *exein_register_status_get_ptr;
extern int exein_interface_ready;
extern struct sock *exein_nl_sk_lsm;
extern int exein_rndkey;

static struct proc_dir_entry *ent;

struct sock *nl_sk = NULL;


static void nl_recv_msg(struct sk_buff *skb) {
	struct nlmsghdr *nlh;
	int pid;
	struct sk_buff *skb_out;
	int msg_size;
	char *msg_ok="ACK";
	char *strout;
	int res;
	int (*exein_payload_process)(void *,int)=exein_payload_process_ptr;

	nlh=(struct nlmsghdr*)skb->data;
	pid = nlh->nlmsg_pid; /*pid of sending process */
	#ifdef EXEIN_PRINT_DEBUG
	printk(KERN_INFO "ExeinLKM - Netlink received from %d\n", pid);
	#endif

	if ((*exein_payload_process)(nlmsg_data(nlh),pid)) {
		skb_out = nlmsg_new(strlen(msg_ok),0);
		if(!skb_out)
			{
			printk(KERN_INFO "ExeinLKM - Failed to allocate new skb\n");
			return;
			}
		nlh=nlmsg_put(skb_out,0,0,NLMSG_DONE,strlen(msg_ok),0);
		NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
		strncpy(nlmsg_data(nlh),msg_ok,strlen(msg_ok));
		res=nlmsg_unicast(nl_sk,skb_out,pid);
		if(res<0) printk(KERN_INFO "Error while sending back to user\n");
		}
}

static ssize_t exeinwrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos)
{
	if (exein_debug==0){
		exein_debug=1;
		#ifdef EXEIN_PRINT_DEBUG
        printk( KERN_INFO "ExeinLKM - debug ENABLED\n");
		#endif
	}else{
		exein_debug=0;
		#ifdef EXEIN_PRINT_DEBUG
		printk( KERN_INFO "ExeinLKM - debug DISABLED\n");
		#endif
	}
	*ppos = count;
	return count;
}

static ssize_t exeinread(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
	int len=0;
	char buff[BUFFLEN];
	char *fn;
	int (*exein_register_status_get)(char *,int)=exein_register_status_get_ptr;


	fn=dentry_path_raw(file->f_path.dentry,buff,BUFFLEN);

#ifdef EXEIN_PRINT_DEBUG
        if (strcmp(fn, "/exein/rndkey")==0){
		if (*ppos==0){
			len+=sprintf(buff,"%d\n",exein_rndkey);
			if(copy_to_user(ubuf,buff,len+1)) {
				return -EFAULT;
				}
			*ppos = len;
			}
		}
#endif

        if (strcmp(fn, "/exein/regs")==0){
                if (*ppos==0){
			len=exein_register_status_get(buff, BUFFLEN);
                        if(copy_to_user(ubuf,buff,len+1)) {
                                return -EFAULT;
                                }
                        *ppos = len;
                        }
                }

        return len;
}

static struct file_operations myops =
{
        .owner = THIS_MODULE,
        .read = exeinread,
        .write = exeinwrite,
};

static int init(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = nl_recv_msg,
		};
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
	if(!nl_sk)
		{
		 printk(KERN_ALERT "ExeinLKM - Error creating socket.\n");
		 return -10;
		}
	exein_nl_sk_lsm=nl_sk ;
	char *dirname="exein";
	struct proc_dir_entry *parent;
	parent=proc_mkdir(dirname,NULL);
	ent=proc_create("debug_ctl",0660,parent,&myops);
#ifdef EXEIN_PRINT_DEBUG
        ent=proc_create("rndkey",0660,parent,&myops);
#endif
	ent=proc_create("regs",0660,parent,&myops);
	exein_interface_ready=1;

	printk(KERN_INFO "ExeinLKM - Interface module load complete. Interface ready.\n");
	return 0;
}

static void cleanup(void)
{
	exein_interface_ready=0;
        proc_remove(ent);
}

module_init(init);
module_exit(cleanup);

