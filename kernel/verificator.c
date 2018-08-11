#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/uaccess.h>
#include <linux/crc16.h>
#include <verificator.h>
#include <linux/kallsyms.h>
#include <linux/sched.h>

typedef long (*access_process_vm_t)(struct task_struct *tsk,
		unsigned long addr, void *buf, int len, int write);
access_process_vm_t access_process_vm_func = 0;

static int is_verificator_opened = 0;

static int verificator_open(struct inode *inode, struct file *file)
{
	if (!capable(CAP_SYS_ADMIN)) {
		return -EPERM;
	}

	if (cmpxchg(&is_verificator_opened, 0, 1)) {
		return -EBUSY;
	}

	return 0;
}

static int verificator_release(struct inode *inode, struct file *file)
{
	(void)cmpxchg(&is_verificator_opened, 1, 0);

	return 0;
}

static bool is_verify_struct_valid(struct verification_struct *args)
{
	return args && (args->vrf_size != 0) && virt_addr_valid(args->vrf_addr);
}

static long verificator_verify_code(struct verificator_verify_struct *args)
{
	char 	*code 	  = NULL;
	size_t  code_sz	  = 0;
	long	code_addr = 0;
	unsigned short crc = 0;

	if (!is_verify_struct_valid((struct verification_struct *)args)) {
		return -EINVAL;
	}

	code_sz = args->vs.vrf_size;
	code_addr = args->vs.vrf_addr;

	code = kzalloc(code_sz, GFP_KERNEL);
	if (code == NULL) {
		printk(KERN_ERR "Cannot allocate memory for copying code\n");
		return -ENOMEM;
	}

	memcpy((void*)code, (const void*)code_addr, code_sz);

	crc = crc16(0, code, code_sz);
	if (crc != args->hash) {
		printk(KERN_ERR "Functions signatures not compatible\n"
			" expected [%u] gotted [%u]\n", args->hash, crc);
	}

	kfree(code);

	return crc;
}

static long verificator_get_diff(struct verificator_get_diff_struct *args)
{
	unsigned long ret = 0;
	unsigned long size;
	void	      *code;
	unsigned char *buf;

	if (!is_verify_struct_valid((struct verification_struct *)args)) {
		printk(KERN_ERR "Cannot verify args\n");
		return -EINVAL;
	}

	size = args->vs.vrf_size+1;
	code = (void*)args->vs.vrf_addr;

	buf = kzalloc(size, GFP_KERNEL);
	if (buf == NULL) {
		printk(KERN_ERR "Cannot kzalloc buffer\n");
		return -ENOMEM;
	}

	memcpy(buf, (void*)code, size);

	ret = access_process_vm_func(current, args->vrd_code, (void*)buf, size, 1);
	printk(KERN_INFO "[%d] bytes of code copyed\n", ret);
	kfree(buf);

	return ret;
}

void disable_write_protect(void)
{
#if defined(__i386__)
	uint32_t cr0_value;
	asm volatile ("movl %%cr0, %0" : "=r" (cr0_value));
	cr0_value &= ~(1 << 16);
	asm volatile ("movl %0, %%cr0" :: "r" (cr0_value));
#elif defined(__amd64__)
	uint64_t cr0_value;
	asm volatile ("movq %%cr0, %0" : "=r" (cr0_value));
	cr0_value &= ~(1 << 16);
	asm volatile ("movq %0, %%cr0" :: "r" (cr0_value));
#else
	#error cannot determine whether i386 or amd64
#endif
}
        
void enable_write_protect(void)
{
#if defined(__i386__)
	uint32_t cr0_value;
	asm volatile ("movl %%cr0, %0" : "=r" (cr0_value));
	cr0_value |= (1 << 16);
	asm volatile ("movl %0, %%cr0" :: "r" (cr0_value));
#elif defined(__amd64__)
	uint64_t cr0_value;
	asm volatile ("movq %%cr0, %0" : "=r" (cr0_value));
	cr0_value |= (1 << 16);
	asm volatile ("movq %0, %%cr0" :: "r" (cr0_value));
#else
	#error cannot determine whether i386 or amd64
#endif
}

static long verificator_restore(struct verificator_restore_struct *args)
{
	void 		*kcode;
	void 	__user 	*ucode;
	size_t  	code_sz	  = 0;
	long		restore_addr = 0;
	int		err;

	if (!is_verify_struct_valid((struct verification_struct *)args)) {
		printk(KERN_ERR "Cannot verify args\n");
		return -EINVAL;
	}

	ucode = args->vrr_code;
	code_sz = args->vs.vrf_size;
	restore_addr = args->vs.vrf_addr;

	kcode = kzalloc(code_sz, GFP_KERNEL);
	if (kcode == NULL) {
		printk(KERN_ERR "Cannot allocate memory for copying code\n");
		return -ENOMEM;
	}

	err = copy_from_user((void*)kcode, (const void*)ucode, code_sz);
	if (err) {
		printk(KERN_ERR "Cannot copy code from user to kernel\n");
		kfree(kcode);
		return err;
	}

	printk(KERN_INFO "Try to restore addr\n");
	disable_write_protect();
	memcpy((void*)restore_addr, kcode, code_sz);
	enable_write_protect();
	printk(KERN_INFO "Restored addr\n");

	kfree(kcode);
	return 0;
}

static long verificator_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int err;
	switch(cmd) {
		case VERIFICATOR_VERIFY_CODE: {
			struct verificator_verify_struct args;

			err = copy_from_user(&args, (const void __user*)arg, sizeof(args));

			return err ? err : verificator_verify_code(&args);
		}
		case VERIFICATOR_GET_DIFF: {
			struct verificator_get_diff_struct args;

			err = copy_from_user(&args, (const void __user*)arg, sizeof(args));

			return err ? err : verificator_get_diff(&args);
		}
		case VERIFICATOR_RESTORE: {
			struct verificator_restore_struct args;

			err = copy_from_user(&args, (const void __user*)arg, sizeof(args));

			return err ? err : verificator_restore(&args);
	 	}
		default:
			printk(KERN_ERR "Unrecornized code value");
			return -EINVAL;
	}
}

static struct file_operations verificator_fops = {
	.open 		= verificator_open,
	.release 	= verificator_release,
	.unlocked_ioctl = verificator_ioctl,
};

static struct miscdevice verificator_dev = {
	.minor = MISC_DYNAMIC_MINOR, 
	.name  = "verificator",
	.fops  = &verificator_fops,
};

static int __init initialize_verificator(void)
{
	int err;

	access_process_vm_func = (access_process_vm_t)kallsyms_lookup_name("access_process_vm");
	if (access_process_vm_func == 0) {
		printk(KERN_ERR "Cannot get access_process_vm addr\n");
		return -EINVAL;
	}

	err = misc_register(&verificator_dev);
	if (err < 0) {
		printk(KERN_ERR "Cannot register misc device\n");
	}

	return err;
}

static void __exit deinitialize_verificator(void)
{

	misc_deregister(&verificator_dev);
}

module_init(initialize_verificator);
module_exit(deinitialize_verificator);

MODULE_LICENSE("GPL");
