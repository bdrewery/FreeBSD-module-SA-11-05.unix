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


static int
hook_bind(struct thread *td, void *uvp)
{
	struct bind_args *uap = uvp;
	struct sockaddr *sa;
	int error;

	if ((error = getsockaddr(&sa, uap->name, uap->namelen)) != 0)
		return (error);

	// Handle FreeBSD-SA-11:05.unix here
	if (sa->sa_family == AF_UNIX) {
		struct sockaddr_un *soun = (struct sockaddr_un*) sa;
		// Validate length
		if (soun->sun_len > sizeof(struct sockaddr_un)) {
			return (EINVAL);
		}
	}

	error = kern_bind(td, uap->s, sa);
	free(sa, M_SONAME);
	return (error);
}

static struct sysent
hook_bind_sysent = {
       1,
       hook_bind			/* sy_call */
};


/*our load function*/
static int
dummy_handler (struct module *module, int cmd, void *arg)
{
 int error = 0;

 switch (cmd) {
  case MOD_LOAD :
   sysent[SYS_bind]=hook_bind_sysent;
  break;
  case MOD_UNLOAD :
   sysent[SYS_bind].sy_call=(sy_call_t*)bind;
  break;
  default :
   error = EINVAL;
  break;
 }
 return error;
}

static moduledata_t syscall_mod = {
 "Intercept",
 dummy_handler,
 NULL
};

DECLARE_MODULE(syscall, syscall_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
