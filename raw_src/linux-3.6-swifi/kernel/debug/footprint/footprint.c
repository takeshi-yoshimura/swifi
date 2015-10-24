#include <linux/kernel.h>
#include <asm/sections.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/kgdb.h>
#include <linux/kdebug.h>
#include <linux/syscalls.h>
#include <asm/pgalloc.h>
#include "footprint_private.h"

static DEFINE_SPINLOCK(fp_lock);
static struct kgdb_io footprint_io;
static int kgdb_activated = 0;

static int footprint_bp_install(unsigned long addr)
{
	int ret;
    unsigned long flags;

	spin_lock_irqsave(&fp_lock, flags);
	ret = dbg_set_sw_break(addr);
	spin_unlock_irqrestore(&fp_lock, flags);
	return ret;
}

static int footprint_bp_activate(void)
{
	int ret;
    unsigned long flags;

	spin_lock_irqsave(&fp_lock, flags);
	ret = dbg_activate_sw_breakpoints();
	spin_unlock_irqrestore(&fp_lock, flags);
	return ret;
}

static void footprint_report(struct kgdb_state * ks)
{
	struct task_struct * tsk = kgdb_info[ks->cpu].task;
	int i;
#ifdef CONFIG_LOCKDEP
    struct held_lock * hl;
#endif

    show_regs(ks->linux_regs);
#ifdef CONFIG_LOCKDEP
    printk(KERN_INFO "Lock:\n");
	for (i = 0, hl = tsk->held_locks; i < tsk->lockdep_depth; i++, hl++) {
		if (!hl || !hl->instance) continue;
		printk(KERN_INFO "[<%lx>] %s\n",
			hl->acquire_ip, hl->instance->name);
	}
#endif
}

int footprint_stub(struct kgdb_state * ks)
{
	unsigned long addr = kgdb_arch_pc(ks->ex_vector, ks->linux_regs);
    unsigned long flags;
	int i, ret = 1;

    ks->pass_exception = 1;
    if (atomic_read(&kgdb_setting_breakpoint)) {
        ks->pass_exception = 0;
        goto resume;
    }
    //printk(KERN_INFO "footprint ip:%lx, addr:%lx\n", ks->linux_regs->ip, addr);
/* first, remove a breakpoint that is responsible for this exception. 
 * if cannot find it (ret != 0), this exception is not int3, but oops or panic.
  */
    //printk(KERN_INFO "footprint remove a breakpoint\n");
	spin_lock_irqsave(&fp_lock, flags);
	dbg_deactivate_sw_breakpoints();
	ret = dbg_remove_sw_break(addr);
	dbg_activate_sw_breakpoints();
	spin_unlock_irqrestore(&fp_lock, flags);
    //printk(KERN_INFO "footprint reporting\n");
/* next, report the present system state. */
	if (ks->err_code == DIE_OOPS || ks->err_code == DIE_PANIC || ks->err_code == 0) {
        printk(KERN_INFO "--------------------footprint start--------------------\n");
        printk(KERN_INFO "failure is manifested at %lx due to oops or panic\n", addr);
        printk(KERN_INFO "--------------------footprint end--------------------\n");
	}else if (ret == 0){
        printk(KERN_INFO "--------------------footprint start--------------------\n");
    	printk(KERN_INFO "recording footprint at %lx due to breakpoint\n", addr);
	    footprint_report(ks);
        printk(KERN_INFO "--------------------footprint end--------------------\n");
        ks->pass_exception = 0;
	}
	if (ret == 0 && addr != ks->linux_regs->ip)
        kgdb_arch_set_pc(ks->linux_regs, addr);

    //printk(KERN_INFO "finalizing footprint_stub\n");
/* finally, get ready to go back to the normal exection. */
resume:
	for_each_present_cpu(i) {
		if (!cpu_online(i)) {
			kgdb_info[i].debuggerinfo = NULL;
			kgdb_info[i].task = NULL;
		}
	}
    gdbstub_state(ks, "c");
    kgdb_info[ks->cpu].ret_state = gdbstub_state(ks, "e");
    if (ks->pass_exception)
        kgdb_info[ks->cpu].ret_state = 1;
	return kgdb_info[ks->cpu].ret_state;
}

static int footprint_init(void) 
{
    int ret = 0;
    memset(&footprint_io, 0, sizeof(struct kgdb_io));
    footprint_io.name = "footprint";
    if (!kgdb_activated) {
        kgdb_activated = !kgdb_activated;
        ret = kgdb_register_io_module(&footprint_io);
    }
    return ret;
}

SYSCALL_DEFINE2(install_bp, unsigned long *, addrs, int, size)
{
	int i, ret = 0;

	for (i = 0; i < size; i++) {
		if (!__kernel_text_address(addrs[i])) {
            printk(KERN_INFO "cannot install a breakpoint for the invalid address :%lx\n", addrs[i]);
			continue;
        }
		ret = footprint_bp_install(addrs[i]);
	}
    return ret;
}

SYSCALL_DEFINE0(activate_bp)
{
    footprint_init();
	footprint_bp_activate();
    return 0;
}

