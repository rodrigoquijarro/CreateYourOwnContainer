#include <iostream>
#include <sched.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <fstream>

int ROD(int status, const char *msg) {
 if(status == -1) {  
    perror(msg); 
    exit(EXIT_FAILURE);
 }
 return status;
}

void write_rule(const char* path, const char* value) {
  int fp = open(path, O_WRONLY | O_APPEND );
  write(fp, value, strlen(value));
  close(fp);
} 

#define CGROUP_FOLDER "/sys/fs/cgroup/pids/container/" 
#define concat(a,b) (a"" b)
void limitProcessCreation() { //Limiting resources
  mkdir( CGROUP_FOLDER, S_IRUSR | S_IWUSR);  // Read & Write
  const char* pid  = std::to_string(getpid()).c_str();

  write_rule(concat(CGROUP_FOLDER, "pids.max"), "5"); 
  write_rule(concat(CGROUP_FOLDER, "notify_on_release"), "1"); 
  write_rule(concat(CGROUP_FOLDER, "cgroup.procs"), pid);
}

char* stack_memory() {  //Allocating memory
  const int stackSize = 65536; //Providing memory for new process
  auto *stack = new (std::nothrow) char[stackSize];

  if (stack == nullptr) { 
    printf("Cannot allocate memory \n");
    exit(EXIT_FAILURE);
  }  

  return stack+stackSize;  //return a pointer to the end of the array, because clone execution load this process the stack grows backward. 
}

void setHostName(std::string hostname) {
  sethostname(hostname.c_str(), hostname.size());
}

void setup_variables() {
  clearenv();  // remove all environment variables for this process.
  setenv("TERM", "xterm-256color", 0); //type of screen
  setenv("PATH", "/bin/:/sbin/:usr/bin:/usr/sbin", 0); //finding binaries for shell
}

template <typename... P> 
int run(P... params) {
  char *args[] = {(
char *)params..., (char *)0};
  
  execvp(args[0], args); 
  perror("execvp"); 
  return 0;
}

int run2(const char *name) {
  char *_args[] = {(char *)name, (char *)0 };
  execvp(name, _args);
}

void setup_root(const char* folder){  // changing the root to isolate host files from container
  chroot(folder);
  chdir("/");
}

template <typename Function>  // Decoupling this program loading from the rest of the child function.
void clone_process(Function&& function, int flags){
 auto pid = ROD( clone(function, stack_memory(), flags, 0), "clone" );

 wait(nullptr); //wait until the child finishes execution
} 

#define lambda(fn_body) [](void *args) ->int { fn_body; };

int rod(void *args) {   //Cloning process with name 'rodcontainer' process

  limitProcessCreation();
  printf("child pid: %d\n", getpid()); //isolate our shell process from the rest of the processes
  setHostName("rodry-container");
  setup_variables();

  setup_root("./root");
  mount("proc", "/proc", "proc", 0, 0); //Mounting /proc file system that comes with Alpine distro
  // 'proc' -> Resource
  // '/proc' -> folder destination
  // 'proc' -> type of file system, in this case procfs. 

  auto runnable = lambda(run("/bin/sh")) // in-line function

  clone_process(runnable, SIGCHLD);

  umount("/proc"); // Releasing the binding with 'proc' before our contained process exits:
  return EXIT_SUCCESS;
}

static int child_fn() {
  printf("New `net` Namespace:\n");
  system("ip link");
  printf("\n\n");
  return 0;
}

int main(int argc, char** argv) {

  printf("parent pid: %d\n", getpid());
  printf("Original `net` Namespace:\n");
  system("ip link");
  printf("\n\n");
  clone_process(rod, CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS | SIGCHLD );

// Cloning:
// rod -> Entry point function
// SIGCHLD -> Tells the process to emit a signal when finished
// CLONE_NEWPID -> Creating a new PID namespace
// CLONE_NEWNET -> Isolating a process into its own network namespace
// CLONE_NEWUTS -> Isolates specific identifiers of the system, like nodename and domainname

  return EXIT_SUCCESS;
}
