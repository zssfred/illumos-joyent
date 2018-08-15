/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2013 Joyent, Inc.  All rights reserved.
 */

/*
 * ARM relocation code
 */

// #include <sys/types.h>
// #include <sys/param.h>
// #include <sys/sysmacros.h>
// #include <sys/systm.h>

#include "reloc.h"

/*
 * TODO We've stubbed out the sdt resolve functions. No reason to even think
 * about those now. It's here so we remember it. The TNF one on the other hand
 * is being left behind. No reason to add it.
 */

// #define	SDT_NOP	0x1ea00000

static int
sdt_reloc_resolve(struct module *mp, char *symname, uint32_t *instr)
{
	_kobj_printf(ops, "NYI: sdt_reloc_resolve");
	return (1);

// 	 * The "statically defined tracing" (SDT) provider for DTrace uses
// 	 * a mechanism similar to TNF, but somewhat simpler.  (Surprise,
// 	 * surprise.)  The SDT mechanism works by replacing calls to the
// 	 * undefined routine __dtrace_probe_[name] with nop instructions.
// 	 * The relocations are logged, and SDT itself will later patch the
// 	 * running binary appropriately.
// 	 *
// 	 * However, because we're in such an ur-phase of this project we're
// 	 * going to nop out the location, but not record it. We should do that
// 	 * at some point.

// 	if (strncmp(symname, sdt_prefix, strlen(sdt_prefix)) != 0)
// 		return (1);

// #ifdef	KOBJ_DEBUG
// 	if (kobj_debug & D_DEBUG) {
// 		_kobj_printf(ops, "sdt_reloc_resolve: not recording %s\n",
// 		    symname);
// 	}
// #endif /* KOBJ_DEBUG */

// 	*instr = SDT_NOP;
// 	return (0);
}

/* Again, largely copied from amd64 */
int
/* ARGSUSED2 */
do_relocate(struct module *mp, char *reltbl, Word relshtype, int nreloc,
	int relocsize, Addr baseaddr)
{
	unsigned long stndx;
	unsigned long off;	/* can't be register for tnf_reloc_resolve() */
	register unsigned long reladdr, rend;
	register unsigned int rtype;
	unsigned long value;
	Elf64_Sxword addend;
	Sym *symref;
	int err = 0;
	int symnum;
	reladdr = (unsigned long)reltbl;
	rend = reladdr + nreloc * relocsize;

#ifdef	KOBJ_DEBUG
	if (kobj_debug & D_RELOCATIONS) {
		_kobj_printf(ops, "krtld:\ttype\t\t\toffset\t   addend"
		    "      symbol\n");
		_kobj_printf(ops, "krtld:\t\t\t\t\t   value\n");
	}
#endif

	symnum = -1;
	/* loop through relocations */
	while (reladdr < rend) {
		symnum++;
		rtype = ELF_R_TYPE(((Rela *)reladdr)->r_info);
		off = ((Rela *)reladdr)->r_offset;
		stndx = ELF_R_SYM(((Rela *)reladdr)->r_info);
		if (stndx >= mp->nsyms) {
			_kobj_printf(ops, "do_relocate: bad stndx %d\n",
			    symnum);
			return (-1);
		}
		if ((rtype > R_AARCH64_NUM) || IS_TLS_INS(rtype)) {
			_kobj_printf(ops, "krtld: invalid relocation type %d",
			    rtype);
			_kobj_printf(ops, " at 0x%llx:", off);
			_kobj_printf(ops, " file=%s\n", mp->filename);
			err = 1;
			continue;
		}


		addend = (long)(((Rela *)reladdr)->r_addend);
		reladdr += relocsize;


		if (rtype == R_AARCH64_NONE)
			continue;

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			Sym *	symp;
			symp = (Sym *)
			    (mp->symtbl+(stndx * mp->symhdr->sh_entsize));
			_kobj_printf(ops, "krtld:\t%s",
			    conv_reloc_AARCH64_type(rtype));
			_kobj_printf(ops, "\t0x%8llx", off);
			_kobj_printf(ops, " 0x%8llx", addend);
			_kobj_printf(ops, "  %s\n",
			    (const char *)mp->strings + symp->st_name);
		}
#endif

		if (!(mp->flags & KOBJ_EXEC))
			off += baseaddr;


		if (rtype == R_AARCH64_RELATIVE) {
			/* XXX not supported yet anyways... */
			value = baseaddr;
		} else {
			/*
			 * get symbol table entry - if symbol is local
			 * value is base address of this object
			 */
			symref = (Sym *)
			    (mp->symtbl+(stndx * mp->symhdr->sh_entsize));

			if (ELF_ST_BIND(symref->st_info) == STB_LOCAL) {
				/* *** this is different for .o and .so */
				value = symref->st_value;
			} else {
				/*
				 * It's global. Allow weak references.  If
				 * the symbol is undefined try to resolve with
				 * sdt. If we ever support tnf, also give
				 * tnf a chance to resolve.
				 */
				if (symref->st_shndx == SHN_UNDEF &&
				    sdt_reloc_resolve(mp, mp->strings +
				    symref->st_name, (uint32_t *)off) == 0)
					continue;

				if (symref->st_shndx == SHN_UNDEF) {
					if (ELF_ST_BIND(symref->st_info)
					    != STB_WEAK) {
						_kobj_printf(ops,
						    "not found: %s\n",
						    mp->strings +
						    symref->st_name);
						err = 1;
					}
					continue;
				} else { /* symbol found  - relocate */
					/*
					 * calculate location of definition
					 * - symbol value plus base address of
					 * containing shared object
					 */
					value = symref->st_value;

				} /* end else symbol found */
			} /* end global or weak */
		} /* end not R_AMD64_RELATIVE */

		value += addend;
		/*
		 * calculate final value -
		 * if PC-relative, subtract ref addr
		 */
		if (IS_PC_RELATIVE(rtype))
			value -= off;

#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "krtld:\t\t\t\t0x%8llx", off);
			_kobj_printf(ops, " 0x%8llx\n", value);
		}
#endif

		if (do_reloc_krtld(rtype, (unsigned char *)off, &value,
		    (const char *)mp->strings + symref->st_name,
		    mp->filename) == 0)
			err = 1;

	} /* end of while loop */
	if (err)
		return (-1);

	return (0);
}

// int
// do_relocate(struct module *mp, char *reltbl, Word relshtype, int nreloc,
//     int relocsize, Addr baseaddr)
// {
// 	_kobj_printf(ops, "NYI: do_relocate");
// 	return (-1);
// 	int symnum;
// 	int err = 0;
// 	unsigned long off, stndx, reladdr, rend, rtype;
// 	long value;
// 	Sym *symref;

// 	reladdr = (unsigned long)reltbl;
// 	rend = reladdr + nreloc * relocsize;

// #ifdef	KOBJ_DEBUG
// 	if (kobj_debug & D_RELOCATIONS) {
// 		_kobj_printf(ops, "krtld:\ttype\t\t\toffset      symbol\n");
// 		_kobj_printf(ops, "krtld:\t\t\t\t\t   value\n");
// 	}
// #endif

// 	while (reladdr < rend) {
// 		symnum++;
// 		rtype = ELF32_R_TYPE(((Rel *)reladdr)->r_info);
// 		off = ((Rel *)reladdr)->r_offset;
// 		stndx = ELF32_R_SYM(((Rel *)reladdr)->r_info);
// 		if (stndx >= mp->nsyms) {
// 			_kobj_printf(ops, "do_relocate: bad stndx %d\n",
// 			    symnum);
// 			return (-1);
// 		}
// 		if ((rtype > R_ARM_NUM) || IS_TLS_INS(rtype)) {
// 			_kobj_printf(ops, "krtld: invalid relocation type %d",
// 			    rtype);
// 			_kobj_printf(ops, " at 0x%llx:", off);
// 			_kobj_printf(ops, " file=%s\n", mp->filename);
// 			err = 1;
// 			continue;
// 		}

// 		reladdr += relocsize;

// 		if (rtype == R_ARM_NONE)
// 			continue;

// 		symref = (Sym *)(mp->symtbl+(stndx * mp->symhdr->sh_entsize));

// #ifdef	KOBJ_DEBUG
// 		if (kobj_debug & D_RELOCATIONS) {
// 			_kobj_printf(ops, "krtld:\t%s",
// 			    conv_reloc_ARM_type(rtype));
// 			_kobj_printf(ops, "\t0x%8x", off);
// 			_kobj_printf(ops, "  %s\n",
// 			    (const char *)mp->strings + symref->st_name);
// 		}
// #endif

// 		if (!(mp->flags & KOBJ_EXEC))
// 			off += baseaddr;

// 		/*
// 		 * XXX ia32 looks for R_386_RELATIVE, but R_ARM_RELATIVE is
// 		 * not supported by us. Seems like we can probably ignore it for
// 		 * now?
// 		 */

// 		 * get symbol table entry - if symbol is local
// 		 * value is base address of this object


// 		if (ELF32_ST_BIND(symref->st_info) == STB_LOCAL) {
// 			/* *** this is different for .o and .so */
// 			value = symref->st_value;
// 		} else {

// 			/*
// 			 * It's global. Allow weak references.  If the symbol is
// 			 * undefined, give SDT a chance to claim it.
// 			 */
// 			if (symref->st_shndx == SHN_UNDEF &&
// 			    sdt_reloc_resolve(mp, mp->strings + symref->st_name,
// 			    (uint32_t *)off) == 0)
// 				continue;

// 			if (symref->st_shndx == SHN_UNDEF) {
// 				if (ELF32_ST_BIND(symref->st_info) !=
// 				    STB_WEAK) {
// 					_kobj_printf(ops, "not found: %s\n",
// 					    mp->strings + symref->st_name);
// 					err = 1;
// 				}
// 				continue;
// 			} else { /* symbol found  - relocate */

// 				/*
// 				 * calculate location of definition - symbol
// 				 * value plus base address of containing shared
// 				 * object
// 				 */
// 				value = symref->st_value;

// 			} /* end else symbol found */
// 		} /* end global or weak */

// 		/*
// 		 * calculate final value -
// 		 * if PC-relative, subtract ref addr
// 		 */
// 		if (IS_PC_RELATIVE(rtype))
// 			value -= off;

// #ifdef	KOBJ_DEBUG
// 		if (kobj_debug & D_RELOCATIONS) {
// 			_kobj_printf(ops, "krtld:\t\t\t\t0x%8x", off);
// 			_kobj_printf(ops, " 0x%8x\n", value);
// 		}
// #endif

// 		if (do_reloc_krtld(rtype, (unsigned char *)off, (Word *)&value,
// 		    (const char *)mp->strings + symref->st_name,
// 		    mp->filename) == 0)
// 			err = 1;

// 	} /* end of while loop */
// 	if (err)
// 		return (-1);

// 	return (0);
// }

/* copied from amd64 version like arm is copied from i386 */
int
do_relocations(struct module *mp)
{
	uint_t shn;
	Shdr *shp, *rshp;
	uint_t nreloc;

	/* do the relocations */
	for (shn = 1; shn < mp->hdr.e_shnum; shn++) {
		rshp = (Shdr *)
		    (mp->shdrs + shn * mp->hdr.e_shentsize);
		if (rshp->sh_type == SHT_REL) {
			_kobj_printf(ops, "%s can't process type SHT_REL\n",
			    mp->filename);
			return (-1);
		}
		if (rshp->sh_type != SHT_RELA)
			continue;
		if (rshp->sh_link != mp->symtbl_section) {
			_kobj_printf(ops, "%s reloc for non-default symtab\n",
			    mp->filename);
			return (-1);
		}
		if (rshp->sh_info >= mp->hdr.e_shnum) {
			_kobj_printf(ops, "do_relocations: %s sh_info ",
			    mp->filename);
			_kobj_printf(ops, "out of range %d\n", shn);
			goto bad;
		}
		nreloc = rshp->sh_size / rshp->sh_entsize;

		/* get the section header that this reloc table refers to */
		shp = (Shdr *)
		    (mp->shdrs + rshp->sh_info * mp->hdr.e_shentsize);

		/*
		 * Do not relocate any section that isn't loaded into memory.
		 * Most commonly this will skip over the .rela.stab* sections
		 */
		if (!(shp->sh_flags & SHF_ALLOC))
			continue;
#ifdef	KOBJ_DEBUG
		if (kobj_debug & D_RELOCATIONS) {
			_kobj_printf(ops, "krtld: relocating: file=%s ",
			    mp->filename);
			_kobj_printf(ops, "section=%d\n", shn);
		}
#endif

		if (do_relocate(mp, (char *)rshp->sh_addr, rshp->sh_type,
		    nreloc, rshp->sh_entsize, shp->sh_addr) < 0) {
			_kobj_printf(ops,
			    "do_relocations: %s do_relocate failed\n",
			    mp->filename);
			goto bad;
		}
		kobj_free((void *)rshp->sh_addr, rshp->sh_size);
		rshp->sh_addr = 0;
	}
	mp->flags |= KOBJ_RELOCATED;
	return (0);
bad:
	kobj_free((void *)rshp->sh_addr, rshp->sh_size);
	rshp->sh_addr = 0;
	return (-1);
}
