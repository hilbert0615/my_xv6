#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "proc.h"
#include "defs.h"

struct cpu cpus[NCPU];

struct proc proc[NPROC];

struct proc *initproc;

int nextpid = 1;
struct spinlock pid_lock;

extern void forkret(void);
static void wakeup1(struct proc *chan);

extern char trampoline[]; // trampoline.S

void procinit(void)
{
  struct proc *p;

  initlock(&pid_lock, "nextpid");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    initlock(&p->lock, "proc");

    // Allocate a page for the process's kernel stack.
    // Map it high in memory, followed by an invalid
    // guard page.
    char *pa = kalloc();
    if (pa == 0)
      panic("kalloc");
    uint64 va = KSTACK((int)(p - proc));
    kvmmap(va, (uint64)pa, PGSIZE, PTE_R | PTE_W);
    p->kstack = va;
  }
  kvminithart();
}

// Must be called with interrupts disabled,
// to prevent race with process being moved
// to a different CPU.
int cpuid()
{
  int id = r_tp();
  return id;
}

// Return this CPU's cpu struct.
// Interrupts must be disabled.
struct cpu *
mycpu(void)
{
  int id = cpuid();
  struct cpu *c = &cpus[id];
  return c;
}

// Return the current struct proc *, or zero if none.
struct proc *
myproc(void)
{
  push_off();
  struct cpu *c = mycpu();
  struct proc *p = c->proc;
  pop_off();
  return p;
}

int allocpid()
{
  int pid;

  acquire(&pid_lock);
  pid = nextpid;
  nextpid = nextpid + 1;
  release(&pid_lock);

  return pid;
}

// Look in the process table for an UNUSED proc.
// If found, initialize state required to run in the kernel,
// and return with p->lock held.
// If there are no free procs, return 0.
static struct proc *
allocproc(void)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->state == UNUSED)
    {
      goto found;
    }
    else
    {
      release(&p->lock);
    }
  }
  return 0;

found:
  p->pid = allocpid();

  // Allocate a trapframe page.
  if ((p->trapframe = (struct trapframe *)kalloc()) == 0)
  {
    release(&p->lock);
    return 0;
  }

  // An empty user page table.
  p->pagetable = proc_pagetable(p);
  p->trap_va = TRAPFRAME;

  // thread metadata defaults
  p->is_thread = 0;
  p->tgroup = p;
  p->ustack = 0;

  // Set up new context to start executing at forkret,
  // which returns to user space.
  memset(&p->context, 0, sizeof(p->context));
  p->context.ra = (uint64)forkret;
  p->context.sp = p->kstack + PGSIZE;

  return p;
}

// free a proc structure and the data hanging from it,
// including user pages.
// p->lock must be held.
static void
freeproc(struct proc *p)
{
  if (p->trapframe)
    kfree((void *)p->trapframe);
  p->trapframe = 0;
  if (p->pagetable)
    proc_freepagetable(p->pagetable, p->sz);
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->state = UNUSED;
}

// Free only thread-specific resources
static void
freeproc_thread(struct proc *p)
{
  // unmap this thread's trapframe mapping from the shared pagetable
  if (p->pagetable && p->trap_va)
  {
    // 仅当该 trap_va 目前确有映射时才解除映射，避免 walk panic
    if (kwalkaddr(p->pagetable, p->trap_va) != 0)
      uvmunmap(p->pagetable, p->trap_va, PGSIZE, 0);
  }

  if (p->trapframe)
    kfree((void *)p->trapframe);

  // clear fields
  p->trapframe = 0;
  p->trap_va = 0;
  p->pagetable = 0;
  p->sz = 0;
  p->pid = 0;
  p->parent = 0;
  p->name[0] = 0;
  p->chan = 0;
  p->killed = 0;
  p->xstate = 0;
  p->is_thread = 0;
  p->tgroup = 0;
  p->ustack = 0;
  p->state = UNUSED;
}

// Create a page table for a given process,
// with no user pages, but with trampoline pages.
pagetable_t
proc_pagetable(struct proc *p)
{
  pagetable_t pagetable;

  // An empty page table.
  pagetable = uvmcreate();

  // map the trampoline code (for system call return)
  // at the highest user virtual address.
  // only the supervisor uses it, on the way
  // to/from user space, so not PTE_U.
  mappages(pagetable, TRAMPOLINE, PGSIZE,
           (uint64)trampoline, PTE_R | PTE_X);

  // map the trapframe just below TRAMPOLINE, for trampoline.S.
  mappages(pagetable, TRAPFRAME, PGSIZE,
           (uint64)(p->trapframe), PTE_R | PTE_W);

  return pagetable;
}

// Free a process's page table, and free the
// physical memory it refers to.
void proc_freepagetable(pagetable_t pagetable, uint64 sz)
{
  uvmunmap(pagetable, TRAMPOLINE, PGSIZE, 0);
  uvmunmap(pagetable, TRAPFRAME, PGSIZE, 0);
  if (sz > 0)
    uvmfree(pagetable, sz);
}

// a user program that calls exec("/init")
// od -t xC initcode
uchar initcode[] = {
    0x17, 0x05, 0x00, 0x00, 0x13, 0x05, 0x45, 0x02,
    0x97, 0x05, 0x00, 0x00, 0x93, 0x85, 0x35, 0x02,
    0x93, 0x08, 0x70, 0x00, 0x73, 0x00, 0x00, 0x00,
    0x93, 0x08, 0x20, 0x00, 0x73, 0x00, 0x00, 0x00,
    0xef, 0xf0, 0x9f, 0xff, 0x2f, 0x69, 0x6e, 0x69,
    0x74, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00};

// Set up first user process.
void userinit(void)
{
  struct proc *p;

  p = allocproc();
  initproc = p;

  // allocate one user page and copy init's instructions
  // and data into it.
  uvminit(p->pagetable, initcode, sizeof(initcode));
  p->sz = PGSIZE;

  // prepare for the very first "return" from kernel to user.
  p->trapframe->epc = 0;     // user program counter
  p->trapframe->sp = PGSIZE; // user stack pointer

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  p->state = RUNNABLE;

  release(&p->lock);
}

// Grow or shrink user memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
  uint sz;
  struct proc *p = myproc();

  sz = p->sz;
  if (n > 0)
  {
    if ((sz = uvmalloc(p->pagetable, sz, sz + n)) == 0)
    {
      return -1;
    }
  }
  else if (n < 0)
  {
    sz = uvmdealloc(p->pagetable, sz, sz + n);
  }
  // 同步所有共享同一页表的线程的 sz（包括自己）
  p->sz = sz;
  for (struct proc *pp = proc; pp < &proc[NPROC]; pp++)
  {
    if (pp == p)
      continue;
    if (pp->state != UNUSED && pp->pagetable == p->pagetable)
    {
      acquire(&pp->lock);
      pp->sz = sz;
      release(&pp->lock);
    }
  }
  return 0;
}

// Create a new process, copying the parent.
// Sets up child kernel stack to return as if from fork() system call.
int fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *p = myproc();

  // Allocate process.
  if ((np = allocproc()) == 0)
  {
    return -1;
  }

  // Copy user memory from parent to child.
  if (uvmcopy(p->pagetable, np->pagetable, p->sz) < 0)
  {
    freeproc(np);
    release(&np->lock);
    return -1;
  }
  np->sz = p->sz;

  np->parent = p;

  // copy saved user registers.
  *(np->trapframe) = *(p->trapframe);

  // Cause fork to return 0 in the child.
  np->trapframe->a0 = 0;

  // increment reference counts on open file descriptors.
  for (i = 0; i < NOFILE; i++)
    if (p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(p->name));

  pid = np->pid;

  np->state = RUNNABLE;

  release(&np->lock);

  return pid;
}

// Pass p's abandoned children to init.
// Caller must hold p->lock.
void reparent(struct proc *p)
{
  struct proc *pp;

  for (pp = proc; pp < &proc[NPROC]; pp++)
  {
    // this code uses pp->parent without holding pp->lock.
    // acquiring the lock first could cause a deadlock
    // if pp or a child of pp were also in exit()
    // and about to try to lock p.
    if (pp->parent == p)
    {
      // pp->parent can't change between the check and the acquire()
      // because only the parent changes it, and we're the parent.
      acquire(&pp->lock);
      pp->parent = initproc;
      // we should wake up init here, but that would require
      // initproc->lock, which would be a deadlock, since we hold
      // the lock on one of init's children (pp). this is why
      // exit() always wakes init (before acquiring any locks).
      release(&pp->lock);
    }
  }
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait().
void exit(int status)
{
  struct proc *p = myproc();

  if (p == initproc)
    panic("init exiting");

  // 线程与进程组长分离处理
  if (p->is_thread)
  {
    struct proc *leader = p->tgroup;
    if (leader)
    {
      acquire(&leader->lock);
      wakeup1(leader);
      release(&leader->lock);
    }

    // 置为 ZOMBIE 后直接进入调度器；按约定 sched 需要在持有 p->lock 的情况下调用
    acquire(&p->lock);
    p->xstate = status;
    p->state = ZOMBIE;

    // 不释放 p->lock，直接 sched 切走
    sched();
    panic("zombie exit (thread)");
  }

  // 仅在组长处关闭一次
  for (int fd = 0; fd < NOFILE; fd++)
  {
    if (p->ofile[fd])
    {
      struct file *f = p->ofile[fd];
      fileclose(f);
      p->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(p->cwd);
  end_op();
  p->cwd = 0;

  acquire(&initproc->lock);
  wakeup1(initproc);
  release(&initproc->lock);

  acquire(&p->lock);
  struct proc *original_parent = p->parent;

  // 在组长退出前，终结并收割所有同组线程，
  for (;;)
  {
    int have_threads = 0;
    int reaped_one = 0;
    for (struct proc *np = proc; np < &proc[NPROC]; np++)
    {
      if (np == p)
        continue;
      if (np->is_thread && np->tgroup == p)
      {
        have_threads = 1;
        acquire(&np->lock);
        if (np->state == ZOMBIE)
        {
          // 解除其 trapframe 映射并释放其结构
          freeproc_thread(np);
          release(&np->lock);
          reaped_one = 1;
          continue;
        }
        // 请求仍在运行/睡眠的线程退出
        np->killed = 1;
        if (np->state == SLEEPING)
          np->state = RUNNABLE;
        release(&np->lock);
      }
    }
    if (!have_threads)
      break; // 无线程可处理
    if (!reaped_one)
    {
      // 暂无可收割线程
      sleep(p, &p->lock);
    }
  }

  // parent-then-child 加锁顺序
  release(&p->lock);

  acquire(&original_parent->lock);

  acquire(&p->lock);

  reparent(p);

  wakeup1(original_parent);

  p->xstate = status;
  p->state = ZOMBIE;

  release(&original_parent->lock);

  // Jump into the scheduler, never to return.
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
int wait(uint64 addr)
{
  struct proc *np;
  int havekids, pid;
  struct proc *p = myproc();

  // hold p->lock for the whole time to avoid lost wakeups from a child's exit().
  acquire(&p->lock);

  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (np = proc; np < &proc[NPROC]; np++)
    {
      if (np->parent == p && np->is_thread == 0)
      {
        acquire(&np->lock);
        havekids = 1;
        if (np->state == ZOMBIE)
        {
          // Found one
          pid = np->pid;
          if (addr != 0 && copyout(p->pagetable, addr, (char *)&np->xstate,
                                   sizeof(np->xstate)) < 0)
          {
            release(&np->lock);
            release(&p->lock);
            return -1;
          }
          freeproc(np);
          release(&np->lock);
          release(&p->lock);
          return pid;
        }
        release(&np->lock);
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || p->killed)
    {
      release(&p->lock);
      return -1;
    }

    // Wait for a child to exit.
    sleep(p, &p->lock); // DOC: wait-sleep
  }
}

// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run.
//  - swtch to start running that process.
//  - eventually that process transfers control
//    via swtch back to the scheduler.
void scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();

  c->proc = 0;
  for (;;)
  {
    // Avoid deadlock by giving devices a chance to interrupt.
    intr_on();

    // Run the for loop with interrupts off to avoid
    // a race between an interrupt and WFI, which would
    // cause a lost wakeup.
    intr_off();

    int found = 0;
    for (p = proc; p < &proc[NPROC]; p++)
    {
      acquire(&p->lock);
      if (p->state == RUNNABLE)
      {
        // Switch to chosen process.  It is the process's job
        // to release its lock and then reacquire it
        // before jumping back to us.
        p->state = RUNNING;
        c->proc = p;
        swtch(&c->scheduler, &p->context);

        // Keeping track of scheduler invocations for the monitor thread
        c->times++;

        // Process is done running for now.
        // It should have changed its p->state before coming back.
        c->proc = 0;

        found = 1;
      }

      // ensure that release() doesn't enable interrupts.
      // again to avoid a race between interrupt and WFI.
      c->intena = 0;

      release(&p->lock);
    }
    if (found == 0)
    {
      asm volatile("wfi");
    }
  }
}

// Switch to scheduler.  Must hold only p->lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->noff, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
  int intena;
  struct proc *p = myproc();

  if (!holding(&p->lock))
    panic("sched p->lock");
  if (mycpu()->noff != 1)
    panic("sched locks");
  if (p->state == RUNNING)
    panic("sched running");
  if (intr_get())
    panic("sched interruptible");

  intena = mycpu()->intena;
  swtch(&p->context, &mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
  struct proc *p = myproc();
  acquire(&p->lock);
  p->state = RUNNABLE;
  sched();
  release(&p->lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch to forkret.
void forkret(void)
{
  static int first = 1;

  // Still holding p->lock from scheduler.
  release(&myproc()->lock);

  if (first)
  {
    // File system initialization must be run in the context of a
    // regular process (e.g., because it calls sleep), and thus cannot
    // be run from main().
    first = 0;
    fsinit(ROOTDEV);
  }

  usertrapret();
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  // Must acquire p->lock in order to
  // change p->state and then call sched.
  // Once we hold p->lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup locks p->lock),
  // so it's okay to release lk.
  if (lk != &p->lock)
  {                    // DOC: sleeplock0
    acquire(&p->lock); // DOC: sleeplock1
    release(lk);
  }

  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if (lk != &p->lock)
  {
    release(&p->lock);
    acquire(lk);
  }
}

// Wake up all processes sleeping on chan.
// Must be called without any p->lock.
void wakeup(void *chan)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->state == SLEEPING && p->chan == chan)
    {
      p->state = RUNNABLE;
    }
    release(&p->lock);
  }
}

// Wake up p if it is sleeping in wait(); used by exit().
// Caller must hold p->lock.
static void
wakeup1(struct proc *p)
{
  if (!holding(&p->lock))
    panic("wakeup1");
  if (p->chan == p && p->state == SLEEPING)
  {
    p->state = RUNNABLE;
  }
}

// Kill the process with the given pid.
// The victim won't exit until it tries to return
// to user space (see usertrap() in trap.c).
int kill(int pid)
{
  struct proc *p;

  for (p = proc; p < &proc[NPROC]; p++)
  {
    acquire(&p->lock);
    if (p->pid == pid)
    {
      p->killed = 1;
      if (p->state == SLEEPING)
      {
        // Wake process from sleep().
        p->state = RUNNABLE;
      }
      release(&p->lock);
      return 0;
    }
    release(&p->lock);
  }
  return -1;
}

// Copy to either a user address, or kernel address,
// depending on usr_dst.
// Returns 0 on success, -1 on error.
int either_copyout(int user_dst, uint64 dst, void *src, uint64 len)
{
  struct proc *p = myproc();
  if (user_dst)
  {
    return copyout(p->pagetable, dst, src, len);
  }
  else
  {
    memmove((char *)dst, src, len);
    return 0;
  }
}

// Copy from either a user address, or kernel address,
// depending on usr_src.
// Returns 0 on success, -1 on error.
int either_copyin(void *dst, int user_src, uint64 src, uint64 len)
{
  struct proc *p = myproc();
  if (user_src)
  {
    return copyin(p->pagetable, dst, src, len);
  }
  else
  {
    memmove(dst, (char *)src, len);
    return 0;
  }
}

// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void procdump(void)
{
  static char *states[] = {
      [UNUSED] "unused",
      [SLEEPING] "sleep ",
      [RUNNABLE] "runble",
      [RUNNING] "run   ",
      [ZOMBIE] "zombie"};
  struct proc *p;
  char *state;

  printf("\n");
  for (p = proc; p < &proc[NPROC]; p++)
  {
    if (p->state == UNUSED)
      continue;
    if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    printf("%d %s %s", p->pid, state, p->name);
    printf("\n");
  }
}

void monitor_thread(void)
{
  volatile struct cpu *mcpus = cpus;
  uint64 prev_times[NCPU];

  for (int c = 0; c < NCPU; c++)
  {
    mcpus[c].times = 0;
    prev_times[c] = 0;
  }

  printf("Monitor thread running on CPU %d\n", cpuid());

  for (;;)
  {
    // Wait for a bit before checking the CPU status again
    for (volatile int j = 0; j < 100000000; j++)
      ;

    for (int c = 0; c < (NCPU - 1); c++)
    {
      // We only want to check cases in which the CPU is not idle
      if (mcpus[c].proc != 0)
      {
        uint64 times = mcpus[c].times;

        // If the scheduler hasn't been invoked for this CPU core since last check,
        // then it appears to be in a deadlock state
        if (times == prev_times[c])
        {
          printf("[Monitor] CPU %d -> No progress for a while on this core!\n", c);
          panic("[Monitor] Detected deadlock on CPU!");
        }
        else
        {
          prev_times[c] = times;
        }
      }
    }
  }
}

// Create a new thread within the current process's address space.
int clone(uint64 fcn, uint64 arg1, uint64 arg2, uint64 stack)
{
  struct proc *p = myproc();
  struct proc *np;
  int i, pid;

  if ((np = allocproc()) == 0)
  {
    return -1;
  }

  // 释放allocproc创建的临时用户页表
  proc_freepagetable(np->pagetable, 0);
  np->pagetable = p->pagetable;
  np->sz = p->sz;

  // Pick a unique virtual address to map this thread's trapframe
  uint64 tfva = TRAPFRAME;
  while (kwalkaddr(p->pagetable, tfva) != 0)
  {
    tfva -= PGSIZE;
    if (tfva < PGSIZE)
    {
      // cleanup minimal: free the trapframe page and give up this slot
      kfree((void *)np->trapframe);
      np->trapframe = 0;
      np->state = UNUSED;
      release(&np->lock);
      return -1;
    }
  }
  if (mappages(p->pagetable, tfva, PGSIZE, (uint64)np->trapframe, PTE_R | PTE_W) != 0)
  {
    kfree((void *)np->trapframe);
    np->trapframe = 0;
    np->state = UNUSED;
    release(&np->lock);
    return -1;
  }
  np->trap_va = tfva;

  // Init
  *(np->trapframe) = *(p->trapframe);
  np->trapframe->epc = fcn;
  np->trapframe->a0 = arg1;
  np->trapframe->a1 = arg2;

  uint64 sp = (stack + PGSIZE) & ~((uint64)16 - 1);
  np->trapframe->sp = sp;

  for (i = 0; i < NOFILE; i++)
    if (p->ofile[i])
      np->ofile[i] = filedup(p->ofile[i]);
  np->cwd = idup(p->cwd);

  safestrcpy(np->name, p->name, sizeof(np->name));

  np->is_thread = 1;
  np->tgroup = p->is_thread ? p->tgroup : p;
  np->parent = np->tgroup; // join() 在组长处统一收割
  np->ustack = stack;

  pid = np->pid;
  np->state = RUNNABLE;
  release(&np->lock);
  return pid;
}

// Wait for a thread (child of the same thread group) to exit
int join(uint64 ustackptr)
{
  struct proc *self = myproc();
  struct proc *leader = self->is_thread ? self->tgroup : self;
  struct proc *np;
  int have_threads;
  int pid;

  // 用组长的锁来唤醒
  acquire(&leader->lock);
  for (;;)
  {
    have_threads = 0;
    for (np = proc; np < &proc[NPROC]; np++)
    {
      if (np == leader)
        continue;
      if (np->is_thread && np->tgroup == leader)
      {
        acquire(&np->lock);
        have_threads = 1;
        if (np->state == ZOMBIE)
        {
          pid = np->pid;

          // 把栈基地址拷回用户 *stack
          if (ustackptr != 0)
          {
            if (copyout(leader->pagetable, ustackptr, (char *)&np->ustack, sizeof(np->ustack)) < 0)
            {
              release(&np->lock);
              release(&leader->lock);
              return -1;
            }
          }

          freeproc_thread(np);
          release(&np->lock);
          release(&leader->lock);
          return pid;
        }
        release(&np->lock);
      }
    }

    if (!have_threads)
    {
      release(&leader->lock);
      return -1;
    }

    sleep(leader, &leader->lock);
  }
}