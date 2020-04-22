/*
 * ldpreloadhook - a quick open/close/ioctl/read/write syscall hooker
 * Copyright (C) 2012 Pau Oliva Fora <pof@eslack.org>
 *
 * Based on vsound 0.6 source code:
 *   Copyright (C) 2004 Nathan Chantrell <nsc@zorg.org>
 *   Copyright (C) 2003 Richard Taylor <r.taylor@bcs.org.uk>
 *   Copyright (C) 2000,2001 Erik de Castro Lopo <erikd@zip.com.au>
 *   Copyright (C) 1999 James Henstridge <james@daa.com.au>
 * Based on esddsp utility that is part of esound:
 *   Copyright (C) 1998, 1999 Manish Singh <yosh@gimp.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * 1) Compile:
 *   gcc -fPIC -c -o hook.o hook.c
 *   gcc -shared -o hook.so hook.o -ldl
 * 2) Usage:
 *   LD_PRELOAD="./hook.so" command
 *   LD_PRELOAD="./hook.so" SPYFILE="/file/to/spy" command
 *   LD_PRELOAD="./hook.so" SPYFILE="/file/to/spy" DELIMITER="***" command
 */
/*
TODO: hook majority if not all libc api calls
TODO: check application user name against whitelist
TODO: check parent application name against whitelist
if uid is root and parent user name is app then die (local priv)
if user name is app and image path is shell then die (remote, user name needs to be in a blacklist)

TODO: write install app that will do:
install hook:
mount -o remount,rw -t yaffs2 /dev/block/mtdblock3 /system
write hook.so to /system/lib
chmod +w /system/etc/mkshrc
add export LD_PRELOAD=/system/lib/hook.so
chmod -w /system/etc/mkshrc
mount -o remount, r -t yaffs2 /dev/block/mtdblock3 /system

uninstall hook:
mount -o remount,rw -t yaffs2 /dev/block/mtdblock3 /system
rm hook.so
chmod +w /system/etc/mkshrc
remove export LD_PRELOAD=/system/lib/hook.so
chmod -w /system/etc/mkshrc
mount -o remount, r -t yaffs2 /dev/block/mtdblock3 /system

TODO: black list:
browser
email
gallery
sms
etc.


TODO: hooks
unistd.h:extern int execle(const char *, const char *, ...);
fcntl.h:extern int  openat(int fd, const char*  path, int  mode, ...);
stdio.h:FILE	*popen(const char *, const char *);

unistd.h:extern int chdir(const char *);
unistd.h:extern int fchdir(int);
unistd.h:extern int chown(const char *, uid_t, gid_t);
unistd.h:extern int fchown(int, uid_t, gid_t);
unistd.h:extern int lchown(const char *, uid_t, gid_t);
unistd.h:extern int chroot(const char *);

include/sys/linux-unistd.h:int              fchmod (int, mode_t);
include/sys/linux-unistd.h:int              fchmodat (int dirfd, const char *path, mode_t mode, int flags);
include/sys/linux-unistd.h:int              chmod (const char*,mode_t);

include/sys/linux-unistd.h:int              mprotect (const void *, size_t, int);
include/sys/mman.h:extern int    mprotect(const void *, size_t, int);

include/sys/linux-unistd.h:int              mkdirat (int dirfd, const char *pathname, mode_t mode);
include/sys/linux-unistd.h:int              mkdir (const char *, mode_t);

include/sys/ptrace.h:extern long ptrace(int request, pid_t pid, void *addr, void *data);

include/stdlib.h:extern int clearenv(void);
include/stdlib.h:extern int putenv(const char *);
include/stdlib.h:extern int unsetenv(const char *);
include/stdlib.h:extern char *getenv(const char *);


COMPLETED: hooks
int execve(const char *filename, char *const argv[], char *const envp[]){
int execvp(const char *file, char *const argv[]){
int execvpe(const char *file, char *const argv[],char *const envp[]){
int execl(const char *path, const char *arg, ...){
int execlp(const char *file, const char *arg, ...){
pid_t fork(void);
pid_t vfork(void);
DIR*             opendir(const char*  dirpath);
DIR*             fdopendir(int fd);
int  open(const char*  path, int  mode, ...);
FILE	*fopen(const char *, const char *);
stdio.h:FILE	*fopen(const char *, const char *);
stdio.h:FILE	*freopen(const char *, const char *, FILE *);
stdio.h:FILE	*fdopen(int, const char *);



TESTED: hooks
int execve(const char *filename, char *const argv[], char *const envp[]){
int open (const char *pathname, int flags, ...){
int close (int fd){
ssize_t read (int fd, void *buf, size_t count){
ssize_t write (int fd, const void *buf, size_t count){	

TODO: find a good api to hook that is called on process creation and lets us do the following
maybe:
__stack_chk_guard or __libc_init or __start

//if parent process is not root
	//if we are
		//die
//else if app name in apps cant run as root list
	//die
//else if app name in apps cant run as different processes list
	//die
//else
	//return

*/



#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#define DPRINTF(format, args...)	fprintf(stderr, format, ## args)

#ifndef RTLD_NEXT
#define RTLD_NEXT ((void *) -1l)
#endif

#define REAL_LIBC RTLD_NEXT

#ifdef __FreeBSD__
typedef unsigned long request_t;
#else
typedef int request_t;
#endif

static int data_w_fd = -1, hook_fd = -1, data_r_fd = -1;

#ifdef __ANDROID__
static const char *data_w_file = "/data/local/tmp/write_data.bin";
static const char *data_r_file = "/data/local/tmp/read_data.bin";
#else
static const char *data_w_file = "/tmp/write_data.bin";
static const char *data_r_file = "/tmp/read_data.bin"; 
#endif

//ssize_t write (int fd, const void *buf, size_t count);
//
//int open (const char *pathname, int flags, ...){
//	//if were not root
//		//if file to open is in bad file list
//			//return fail
//	//return good
//	static int (*func_open) (const char *, int, mode_t) = NULL;
//	va_list args;
//	mode_t mode;
//	int fd;
//
//	int pid = getpid();
//
//	setenv("SPYFILE", "spyfile", 0);
//	char *spy_file = getenv("SPYFILE");
//
//	if (!func_open)
//		func_open = (int (*) (const char *, int, mode_t)) dlsym (REAL_LIBC, "open");
//
//	va_start (args, flags);
//	mode = va_arg (args, int);
//	va_end (args);
///
//	if (strcmp (pathname, spy_file)){	
//		fd = func_open (pathname, flags, mode);
//
//		DPRINTF ("HOOK(%d): opened file %s (fd=%d)\n", pid, pathname, fd);
//		return fd;
//	}
//
//	data_w_fd = func_open (data_w_file, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
//	data_r_fd = func_open (data_r_file, O_WRONLY|O_CREAT|O_APPEND, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
//	hook_fd = func_open (pathname, flags, mode);
//
//	/* write the delimiter each time we open the files */
//	if (getenv("DELIMITER") != NULL) {
//		write (data_r_fd, getenv("DELIMITER"), strlen(getenv("DELIMITER")));
//		write (data_w_fd, getenv("DELIMITER"), strlen(getenv("DELIMITER")));
//	}
//	
//	
//	DPRINTF ("HOOK(%d): opened hooked file %s (fd=%d)\n", pid, pathname, hook_fd);
//
//	return hook_fd;
//}


int execve(const char *filename, char *const argv[], char *const envp[]){
	//if parent process is app in app block list
		//return fail
	//return good
	static int (*func_execve) (const char *, char *const *, char *const *) = NULL;
	int retval = 0;

	if (!func_execve){
		func_execve = (int (*)(const char *, char *const *, char *const *)) dlsym (REAL_LIBC, "execve");
	}

	DPRINTF ("HOOK: execve  %s \n", filename);

	retval = func_execve(filename, argv, envp);
	return retval;
}


/*
//the following hooks are not tested

FILE *fopen(const char *path, const char *mode){
	static int (*func_fopen) (const char *, const char *) = NULL;
	int retval = 0;

	if (!func_fopen)
		func_fopen = (int (*) (const char *, const char *)) dlsym (REAL_LIBC, "fopen");

	DPRINTF ("HOOK: fopen  %s %s \n", path, mode);

	retval = func_fopen(path, mode);
	return retval;
}


FILE *freopen(const char *path, const char *mode, FILE *stream){
	static int (*func_freopen) (const char *, const char *, FILE *) = NULL;
	int retval = 0;

	if (!func_freopen)
		func_freopen = (int (*) (const char *, const char *, FILE *)) dlsym (REAL_LIBC, "freopen");

	DPRINTF ("HOOK: freopen  %s %s %d\n", path, mode, stream);

	retval = func_freopen(path, mode, stream);
	return retval;
}


FILE *fdopen(int fd, const char *mode){
	static int (*func_fdopen) (int, const char *) = NULL;
	int retval = 0;

	if (!func_fdopen)
		func_fdopen = (int (*) (int, const char *)) dlsym (REAL_LIBC, "fdopen");

	DPRINTF ("HOOK: fdopen  %d %s \n", fd, mode);

	retval = func_fdopen(fd, mode);
	return retval;
}


DIR *opendir(const char *dirpath){
	static int (*func_opendir)(const char *) = NULL;
	DIR *retval = 0;
	
	if (!func_opendir){
		func_opendir = (DIR *(*)(const char *)) dlsym (REAL_LIBC, "opendir");
	}
	DPRINTF("HOOK: opendir %s\n", dirpath);
	retval = func_opendir(dirpath);
	return retval;
}

DIR *fdopendir(int fd){
	static int (*func_fdopendir)(int) = NULL;
	DIR *retval = 0;
	
	if (!func_fdopendir){
		func_fdopendir = (DIR *(*)(int)) dlsym (REAL_LIBC, "fdopendir");
	}
	DPRINTF("HOOK: fdopendir %d\n", fd);
	retval = func_fdopendir(fd);
	return retval;
}


pid_t fork(void){
	//if counter is > MAX_FORK
		//if #current processes is close to NPROC_LIMIT
			//return fail
	//return good
	static int (*func_fork)(void) = NULL;
	pid_t retval = 0;
	
	if (!func_fork){
		func_fork = (pid_t (*)(void)) dlsym (REAL_LIBC, "fork");
	}
	DPRINTF("HOOK: fork \n");
	retval = func_fork();
	return retval;
}


pid_t vfork(void){
	static int (*func_vfork)(void) = NULL;
	pid_t retval = 0;
	
	if (!func_vfork){
		func_vfork = (pid_t (*)(void)) dlsym (REAL_LIBC, "vfork");
	}
	DPRINTF("HOOK: vfork \n");
	retval = func_vfork();
	return retval;
}


int execvp(const char *file, char *const argv[]){
	static int (*func_execvp)(const char *, char *const *) = NULL;
	int retval = 0;

	if (!func_execvp){
		func_execvp = (int (*)(const char *, char *const *)) dlsym (REAL_LIBC, "execvp");
	}

	DPRINTF ("HOOK: execvp  %s \n", file);

	retval = func_execvp(file, argv);
	return retval;	
}


int execvpe(const char *file, char *const argv[],char *const envp[]){
	static int (*func_execvpe)(const char *, char *const *, char *const *) = NULL;
	int retval = 0;

	if (!func_execvpe){
		func_execvpe = (int (*)(const char *, char *const *, char *const *)) dlsym (REAL_LIBC, "execvpe");
	}

	DPRINTF ("HOOK: execvpe  %s \n", file);

	retval = func_execvpe(file, argv, envp);
	return retval;	
}

int execl(const char *path, const char *arg, ...){
	static int (*func_execl)(const char *, const char *, void *) = NULL;
	int retval = 0;
	void *argp;

	if (!func_execl){
		func_execl = (int (*)(const char *, const char *, void *)) dlsym (REAL_LIBC, "execl");
	}
	DPRINTF ("HOOK: execl  %s \n", path);

	retval = func_execl(path, arg, argp);
	return retval;
}


int execlp(const char *file, const char *arg, ...){
	static int (*func_execlp)(const char *, const char *, void *) = NULL;
	int retval = 0;
	void *argp;

	if (!func_execlp){
		func_execlp = (int (*)(const char *, const char *, void *)) dlsym (REAL_LIBC, "execlp");
	}
	DPRINTF ("HOOK: execlp  %s \n", file);

	retval = func_execlp(file, arg, argp);
	return retval;

}
*/


//int close (int fd){	
//
//	static int (*func_close) (int) = NULL;
//	int retval = 0;
//
//	setenv("SPYFILE", "spyfile", 0);
//	char *spy_file = getenv("SPYFILE");
//
//	if (! func_close)
//		func_close = (int (*) (int)) dlsym (REAL_LIBC, "close");


//	if (fd == hook_fd)
//		DPRINTF ("HOOK: closed hooked file %s (fd=%d)\n", spy_file, fd);
//	else
//		DPRINTF ("HOOK: closed file descriptor (fd=%d)\n", fd);
//		
//	retval = func_close (fd);
//	return retval;
//}

//int ioctl (int fd, request_t request, ...){	
//
//	static int (*func_ioctl) (int, request_t, void *) = NULL;
//	va_list args;
//	void *argp;

//	setenv("SPYFILE", "spyfile", 0);
//	char *spy_file = getenv("SPYFILE");

//	if (! func_ioctl)
//		func_ioctl = (int (*) (int, request_t, void *)) dlsym (REAL_LIBC, "ioctl");
//	va_start (args, request);
//	argp = va_arg (args, void *);
//	va_end (args);

//	if (fd != hook_fd) {
//		DPRINTF ("HOOK: ioctl (fd=%d)\n", fd);
//		return func_ioctl (fd, request, argp);
//	} 
//	
//	DPRINTF ("HOOK: ioctl on hooked file %s (fd=%d)\n", spy_file, fd);

	/* Capture the ioctl() calls */
//	return func_ioctl (hook_fd, request, argp);
//}

//ssize_t read (int fd, void *buf, size_t count){	
//
//	static ssize_t (*func_read) (int, const void*, size_t) = NULL;
//	static ssize_t (*func_write) (int, const void*, size_t) = NULL;
//
//	ssize_t retval = 0;

//	setenv("SPYFILE", "spyfile", 0);
//	char *spy_file = getenv("SPYFILE");

//	if (! func_read)
//		func_read = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "read");
//	if (! func_write)
//		func_write = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "write");

//	if (fd != hook_fd) {
//		DPRINTF ("HOOK: read %d bytes from file descriptor (fd=%d)\n", count, fd);
//		return func_read (fd, buf, count);
//	}
//
//	DPRINTF ("HOOK: read %d bytes from hooked file %s (fd=%d)\n", count, spy_file, fd);

//	retval = func_read(fd, buf, count);

//	char *buf2 = calloc(retval, sizeof(char));
//	memcpy(buf2, buf, retval);
//
//	func_write (data_r_fd, buf2, retval);
//	free(buf2);

//	return retval;
//}

//ssize_t write (int fd, const void *buf, size_t count){	

//	static ssize_t (*func_write) (int, const void*, size_t) = NULL;
//	ssize_t retval = 0;

//	setenv("SPYFILE", "spyfile", 0);
//	char *spy_file = getenv("SPYFILE");

//	if (! func_write)
//		func_write = (ssize_t (*) (int, const void*, size_t)) dlsym (REAL_LIBC, "write");

//	if (fd != hook_fd) {
//		DPRINTF ("HOOK: write %d bytes to file descriptor (fd=%d)\n", count, fd);
//		return func_write (fd, buf, count);
//	}

//	DPRINTF ("HOOK: write %d bytes to hooked file %s (fd=%d)\n", count, spy_file, fd);

//	func_write (hook_fd, buf, count);
//	retval = func_write (data_w_fd, buf, count);

//	return retval;
//}
