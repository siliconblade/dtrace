#!/usr/sbin/dtrace -s

/* getdirentries64 args: (int fd, user_addr_t bufp, user_size_t bufsize, ssize_t *bytesread, off_t *offset, int flags) */
/* returns buffer size */
/*
 The following is the struct for a directory entry:
 #define __DARWIN_STRUCT_DIRENTRY { \
	__uint64_t  d_ino;      // file number of entry 
	__uint64_t  d_seekoff;  // seek offset (optional, used by servers) 
	__uint16_t  d_reclen;   // length of this record 
	__uint16_t  d_namlen;   // length of string in d_name 
	__uint8_t   d_type;     // file type, see below 
	char      d_name[__DARWIN_MAXPATHLEN]; // entry name (up to MAXPATHLEN bytes) 
 }
*/

self size_t buf_size;

syscall::getdirentries64:entry 
/fds[arg0].fi_pathname+2 == "/private/tmp"/
{
  /* save the direntries buffer */
  self->buf = arg1;
}

syscall::getdirentries64:return 
/self->buf && arg1 > 0/
{
  /* arg0 contains the actual size of the direntries buffer */
  self->buf_size =  arg0;

  self->ent0 = (struct direntry *) copyin(self->buf, self->buf_size);
  printf("\nFirst Entry: %s\n",self->ent0->d_name);

  self->ent1 = (struct direntry *) (char *)(((char *) self->ent0) + self->ent0->d_reclen);
  printf("Second Entry: %s\n",self->ent1->d_name);

  self->ent2 = (struct direntry *) (char *)(((char *) self->ent1) + self->ent1->d_reclen);
  printf("Hiding Third Entry: %s\n",self->ent2->d_name);

  self->ent3 = (struct direntry *) (char *)(((char *) self->ent2) + self->ent2->d_reclen);

  /* recalculate buffer size cause it'll be smaller after overwriting hidden entry with next entry */
  size_left = self->buf_size - ((char *)self->ent2 - (char *)self->ent0);

  /* copy next entry and following entries to start of hidden entry */
  bcopy((char *)self->ent3, (char *)self->ent2, size_left);

  /* rewrite returned arg for getdirentries64 */
  copyout(self->ent0, self->buf, self->buf_size);

}

syscall::getdirentries64:return 
/self->buf && self->buf_size/
{
  self->buf = 0;  
  self->buf_size = 0;
}


