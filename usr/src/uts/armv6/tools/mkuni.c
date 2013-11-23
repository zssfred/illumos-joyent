/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * For the current ARM fake uniboot we need to combine unix and the boot
 * archive. We have three sections, the initial header, unix, and the boot
 * archive. Each is aligned to a 4k boundary to aid memory mapping.
 */

#include <loader/fakeloader.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysmacros.h>

int
main(int argc, const char *argv[])
{
	int ufd, bfd, ofd;
	size_t rem, tow;
	fakeloader_hdr_t hdr;
	struct stat ustat, bstat;
	char buf[4096];

	if (argc != 4) {
		fprintf(stderr, "mkuni: unix boot-archive output\n");
		return (1);
	}

	if ((ufd = open(argv[1], O_RDONLY)) < 0) {
		perror("open unix");
		return (1);
	}

	if (fstat(ufd, &ustat) != 0) {
		perror("fstat unix");
		return (1);
	}

	if ((bfd = open(argv[2], O_RDONLY)) < 0) {
		perror("open boot archive");
		return (1);
	}

	if (fstat(bfd, &bstat) != 0) {
		perror("fstat boot archive");
		return (1);
	}

	if ((ofd = open(argv[3], O_RDWR | O_CREAT | O_TRUNC, 0644)) < 0) {
		perror("open output file");
		return (1);
	}

	hdr.fh_magic[0] = FH_MAGIC0;
	hdr.fh_magic[1] = FH_MAGIC1;
	hdr.fh_magic[2] = FH_MAGIC2;
	hdr.fh_magic[3] = FH_MAGIC3;
	hdr.fh_unix_size = ustat.st_size;
	hdr.fh_unix_offset = 4096;	/* Unix is always at 4k */
	hdr.fh_archive_size = bstat.st_size;
	hdr.fh_archive_offset = hdr.fh_unix_offset + hdr.fh_unix_size;
	hdr.fh_archive_offset &= ~0xefff;
	hdr.fh_archive_offset += 0x1000;	/* align to next 4k slot */

	printf("unix size: %x\nunix offset: %x\narchive_size %x\n"
	    "archive offset %x\n", hdr.fh_unix_size, hdr.fh_unix_offset,
	    hdr.fh_archive_size, hdr.fh_archive_offset);

	if (write(ofd, &hdr, sizeof (hdr)) != sizeof (hdr)) {
		perror("write header");
		return (1);
	}

	if (lseek(ofd, hdr.fh_unix_offset, SEEK_SET) != hdr.fh_unix_offset) {
		perror("seek for unix");
		return (1);
	}

	rem = hdr.fh_unix_size;
	while (rem != 0) {
		tow = MIN(rem, 4096);
		if (read(ufd, buf, tow) != tow) {
			perror("read unix");
			return (1);
		}
		if (write(ofd, buf, tow) != tow) {
			perror("write unix");
			return (1);
		}
		rem -= tow;
	}

	if (lseek(ofd, hdr.fh_archive_offset, SEEK_SET) !=
	    hdr.fh_archive_offset) {
		perror("seek for boot archive");
		return (1);
	}

	rem = hdr.fh_archive_size;
	while (rem != 0) {
		tow = MIN(rem, 4096);
		if (read(bfd, buf, tow) != tow) {
			perror("read boot archive");
			return (1);
		}
		if (write(ofd, buf, tow) != tow) {
			perror("write boot archive");
			return (1);
		}
		rem -= tow;
	}

	if (close(ufd) != 0) {
		perror("close unix");
		return (1);
	}

	if (close(bfd) != 0) {
		perror("close boot archive");
		return (1);
	}

	if (close(ofd) != 0) {
		perror("close output file");
		return (1);
	}

	return (0);
}
