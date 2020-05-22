# libexnl

This library is intended to be used for interfacing the machine learning engine with the kernel infrastructure.
The function exports four functions:
-  **exein_agent_start**: starts the agent, perform the registration for a particular **tag**, keeps it alive, and manages netlink communication with the kernel.
- **exein_agent_stop**: deallocates all the structure needed by *exein_agent_start* and stops all the side  processes.
- **exein_fetch_data**: request snapshot of the particular PID behavior. 
- **exein_block_process**: Requests a process to be stopped to the kernel 
- **exein_remove_pid**: deallocates resources used by a PID which operates no more.
- **exein_new_pid_notify_cb**:  Pointer to a callback function that is executed when new PID for the monitored task appears
- **exein_delete_pid_cb**: Pointer to a callback function that is executed when PID for the monitored task is terminated


----------------------------------------------------------------------------------------------------
## exein_agent_start

Starts the agent, perform the registration for a particular **tag**, keeps it alive, and manages netlink communication with the kernel. The agent  starts by performing the netlink registration to the kernel interface. If the registration succeeds it runs two pthreads, one for keeping alive the registration, another to manage all the netlink communications. It returns the pointer to the structure controlling the agent operations.

### Interface
```
exein_shandle *exein_agent_start(uint32_t key, uint16_t tag);
```
### Arguments
| Parameter | Type      | Description                |
|:----------|:----------|:---------------------------|
| key       | uint32_t  | Shared secret              |
| tag       | uint16_t  | Tag the agent must register|

### Remarks
 - **key**: it is the per build key that kernel needs as proof that message is authorized. In the debug version of the LSM, this number can be obtained by *cat /proc/exein/rndkey*. In the non-debug version, the key can be only taken from the generated code in the file *security/exein/exein_nn_def.h*, the symbol is **SEEDRND**.
 - **tag**: indicates the process class the client wants to receive feed of.

 The returning value is a pointer to the following structure:
```
typedef struct {
	struct sockaddr_nl	*src_addr, *dest_addr;
	struct msghdr		*msg_rf, *msg_sk;
	struct nlmsghdr		*nlh_rf, *nlh_sk;
	exein_buffers		*data;
	int			sock_fd;
	void			*sk_stack, *rf_stack;
	pid_t			sk_pid, rf_pid, cpid;
	int			trouble;
} exein_shandle;
```
## exein_agent_stop

Terminates an instance of the agent deallocating all the structures used and terminating all the threads spawn.

### Interface
```
void exein_agent_stop(exein_shandle *uhandle);
```
### Arguments
| Parameter | Type             | Description                           |
|:----------|:-----------------|:--------------------------------------|
| uhandle   | exein_shandle *  | Pointer to the structure of the agent |

### Remarks
The handle **exein_agent_start** return value have to been used to terminate the agent together with 
**exein_agent_stop** in order to interrupt the operation that it started.

## exein_fetch_data
Requests a snapshot of data to the kernel and copies it to the userspace application.
### Interface
```
int exein_fetch_data(exein_shandle *uhandle, uint16_t pid, uint16_t *dstbuf);
```
### Arguments
| Parameter | Type             | Description                                            |
|:----------|:-----------------|:-------------------------------------------------------|
| uhandle   | exein_shandle *  | Pointer to the structure  of the agent                 |
| pid       | uint16_t         | pid of the target process                              |
| dstbuf    | uint16_t *       | pointer to preallocated buffer where copy required data|

### Remarks
On linux systems PID is a 32 bit value. Traditionally PID numbers are limited to 32767, in this context uint16_t is appropriate for representing the PID.

## exein_block_process
The function the userspace application must use to send messages to the kernel for terminate offending process.
### Interface
```
int exein_block_process(exein_shandle *uhandle, uint16_t pid, uint32_t key, uint16_t tag);
```
### Arguments
| Parameter | Type             | Description                                            |
|:----------|:-----------------|:-------------------------------------------------------|
| uhandle   | exein_shandle *  | Pointer to the structure  of the agent                 |
| pid       | uint16_t         | pid of the target process                              |
| key       | uint32_t         | Shared secret                                          |
| tag       | uint16_t         | The tag the agent registered for                       |

