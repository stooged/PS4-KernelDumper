/*****************************************************************
*
* ============== Kernel Dumper for PS4 - WildCard ===============
*
*	Support for 5.05
*
*	Thanks to:
*	-Qwertyuiop for his kernel exploits
* 	-Specter for his Code Execution method
*	-IDC for helping to understand things
*	-Shadow for the copyout trick ;)
*
******************************************************************/
#include "ps4.h"
#include "defines.h"

char usb_mount_path[256];

int kdump(struct thread *td, struct kdump_args* args){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_BASE_PTR];


	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + KERN_COPYOUT);
	void (*bzero)(void *b, size_t len) = (void *)(kernel_base + KERN_BZERO);

	// pull in our arguments
  	uint64_t kaddr = args->payload_info_dumper->kaddr;
	uint64_t uaddr = args->payload_info_dumper->uaddr;

	// run copyout into userland memory for the kaddr we specify
	int cpRet = copyout(kaddr, uaddr , PAGE_SIZE);

	// if mapping doesnt exist zero out that mem
	if(cpRet == -1){
	
		bzero(uaddr, PAGE_SIZE);
		return cpRet;
	}
	
	return cpRet;
}


int kpayload(struct thread *td,struct kpayload_args* args){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-KERN_BASE_PTR];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[KERN_PRISON0];
	void** got_rootvnode = (void**)&kernel_ptr[KERN_ROOTVNODE];

	// resolve kernel functions


	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + KERN_COPYOUT);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);
	
	// Restore write protection
	writeCr0(cr0);

	uint64_t uaddr = args->payload_info->uaddr;

	copyout(&kernel_base, uaddr, 8);

	return 0;
}




char* getusbpath()
{
    int usbdir;
    char tmppath[64];
    char tmpusb[64];
    tmpusb[0] = '\0';
    char *retval;
    for (int x = 0; x <= 7; x++)
    {
       sprintf(tmppath, "/mnt/usb%i/.dirtest", x);
       usbdir = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0777);
       if (usbdir != -1)
       {
         close(usbdir);
         unlink(tmppath);
         sprintf(tmpusb, "/mnt/usb%i", x); 
         retval = malloc (sizeof (char) * 10);
         strcpy(retval, tmpusb);
         return retval;
       }
    }
     return NULL;
}




int _main(struct thread *td){

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	uint64_t* dump = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	uint64_t filedump = mmap(NULL, KERN_DUMPSIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	// patch some things in the kernel (sandbox, prison, debug settings etc..)
	
  	struct payload_info payload_info;

	payload_info.uaddr = dump;

	kexec(&kpayload,&payload_info);

	// resolve notifications after we have access to full fs
	initSysUtil();


    char* usb_mnt_path = getusbpath();
    if (usb_mnt_path != NULL)
    {
	sprintf(usb_mount_path, "%s", usb_mnt_path);
	free(usb_mnt_path);

	notify("Kernel patched!");

	// retreive the kernel base copied into userland memory and set it

	uint64_t kbase;

	memcpy(&kbase,dump,8);

	// loop on our kdump payload 
	
	uint64_t pos = 0;
  	struct payload_info_dumper payload_info_dumper;

	notify("Starting Kernel Dump...");

	// loop enough to dump up until gpu used memory
	for(int i = 0; i < KERN_DUMPITER; i++){
	
 		payload_info_dumper.kaddr = kbase + pos;

		payload_info_dumper.uaddr = filedump + pos;

		// call our copyout wrapper and send the userland buffer over socket
		kexec(&kdump, &payload_info_dumper);

		pos = pos + PAGE_SIZE;
	}
	
	notify("Finished dumping Kernel to userland!");	
	
        char tmppath[256];
        sprintf(tmppath, "%s/KernelDump.bin", usb_mount_path);
        char tmpmsg[256];
        sprintf(tmpmsg, "Writing kernel to:\n%s", tmppath);
        notify(tmpmsg);

	// write to file
    	int fd = open(tmppath, O_WRONLY | O_CREAT | O_TRUNC, 0777);			

	if(fd == -1) 
	{
		notify("Cant create file :/");
	}
	
	else
	{
		write(fd, filedump, KERN_DUMPSIZE);
	
		notify("Finished writing Kernel to a File :)");
		close(fd);
	}

	munmap(dump, PAGE_SIZE);
	munmap(filedump, KERN_DUMPSIZE);


      }
      else
      {
      notify("No USB Found");
      }
	return 0;
}


