#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/linker.h>
#include <sys/sysproto.h>
#include <sys/sysent.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/socketvar.h>
#include <sys/syscallsubr.h>
#include <sys/un.h>

// Handle FreeBSD-SA-11:05.unix here
static int
validate_sun_len(struct thread *td, struct sockaddr* sa)
{
	if (sa->sa_family == AF_UNIX) {
		struct sockaddr_un *soun = (struct sockaddr_un*) sa;
		// Validate length
		if (soun->sun_len > sizeof(struct sockaddr_un)) {
			printf("BLOCKED SA-11:05.unix uid(%d) pid(%d) ppid(%d) path(%s)\n", td->td_ucred->cr_uid, td->td_proc->p_pid, td->td_proc->p_pptr->p_pid, soun->sun_path);
			return 1;
		}
	}
	return 0;
}

static int
hook_bind(struct thread *td, void *uvp)
{
	struct bind_args *uap = uvp;
	struct sockaddr *sa;
	int error;

	if ((error = getsockaddr(&sa, uap->name, uap->namelen)) != 0)
		return (error);

	// Handle FreeBSD-SA-11:05.unix here
	if (validate_sun_len(td, sa)) {
		free(sa, M_SONAME);
		return (EINVAL);
	}

	error = kern_bind(td, uap->s, sa);
	free(sa, M_SONAME);
	return (error);
}

static int
hook_connect(struct thread *td, void *uvp)
{
	struct connect_args *uap = uvp;
	struct sockaddr *sa;
	int error;

	error = getsockaddr(&sa, uap->name, uap->namelen);
	if (error)
		return (error);

	// Handle FreeBSD-SA-11:05.unix here
	if (validate_sun_len(td, sa)) {
		free(sa, M_SONAME);
		return (EINVAL);
	}

	error = kern_connect(td, uap->s, sa);
	free(sa, M_SONAME);
	return (error);
}

/*our load function*/
static int
dummy_handler (struct module *module, int cmd, void *arg)
{
 int error = 0;

 switch (cmd) {
  case MOD_LOAD :
   sysent[SYS_bind].sy_call=(sy_call_t*)hook_bind;
   sysent[SYS_connect].sy_call=(sy_call_t*)hook_connect;
  break;
  case MOD_UNLOAD :
   sysent[SYS_bind].sy_call=(sy_call_t*)bind;
   sysent[SYS_connect].sy_call=(sy_call_t*)connect;
  break;
  default :
   error = EINVAL;
  break;
 }
 return error;
}

static moduledata_t syscall_mod = {
 "SA-11:05.unix",
 dummy_handler,
 NULL
};

DECLARE_MODULE(syscall, syscall_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
