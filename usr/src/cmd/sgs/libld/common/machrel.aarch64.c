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
 * Portions:
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#define	DO_RELOC_LIBLD_ARM
#ifndef _ELF64
#define _ELF64
/*
 * Seems to be necessary for getting the correct machdep_arm data when
 * cross building
 */
#endif

#include	<sys/elf_AARCH64.h>
#include	<stdio.h>
#include	<debug.h>
#include	<reloc.h>
#include	<arm/machdep_arm.h>
#include	"msg.h"
#include	"_libld.h"

static Word
ld_init_rel(Rel_desc *reld, Word *typedata, void *reloc)
{
	Rela	*rel = (Rela *)reloc;

	reld->rel_rtype = (Word)ELF_R_TYPE(rel->r_info, M_MACH);
	reld->rel_roffset = rel->r_offset;
	reld->rel_raddend = rel->r_addend;
	*typedata = (Word)ELF_R_TYPE_DATA(rel->r_info);

	return ((Word)ELF_R_SYM(rel->r_info));
}

static void
ld_mach_eflags(Ehdr *ehdr, Ofl_desc *ofl)
{
	/*
	 * XXXAARCH64: arm says:
	 * we want some kind of compatibility checking for input flags
	 * here, and to bail if we it's wrong.
	 */
	ofl->ofl_dehdr->e_flags |= ehdr->e_flags;

}

/* XXXARCH64: every arch does this same way */
static void
ld_mach_make_dynamic(Ofl_desc *ofl, size_t *cnt)
{
	if (!(ofl->ofl_flags & FLG_OF_RELOBJ)) {
		/* Create this entry if we are going to create a PLT. */
		if (ofl->ofl_pltcnt > 0)
			(*cnt)++; /* DT_PLTGOT */
	}
}

/* XXXARCH64: every arch does this same way */
static void
ld_mach_update_odynamic(Ofl_desc *ofl, Dyn **dyn)
{
	if (((ofl->ofl_flags & FLG_OF_RELOBJ) == 0) && ofl->ofl_pltcnt) {
		(*dyn)->d_tag = DT_PLTGOT;
		if (ofl->ofl_osgot)
			(*dyn)->d_un.d_ptr = ofl->ofl_osgot->os_shdr->sh_addr;
		else
			(*dyn)->d_un.d_ptr = 0;
		(*dyn)++;
	}
}

/* XXXARCH64: every arch does this same way */
static Xword
ld_calc_plt_addr(Sym_desc *sdp, Ofl_desc *ofl)
{
	Xword	value;

	value = (Xword)(ofl->ofl_osplt->os_shdr->sh_addr) +
	    M_PLT_RESERVSZ + ((sdp->sd_aux->sa_PLTndx - 1) * M_PLT_ENTSIZE);
	return (value);
}

/* ARGSUSED */ /* XXXARCH64: same as amd for now */
static Gotndx *
ld_find_got_ndx(Alist *alp, Gotref gref, Ofl_desc *ofl, Rel_desc *rdesc)
{

	Aliste	idx;
	Gotndx	*gnp;

	assert(rdesc != 0);

	if ((gref == GOT_REF_TLSLD) && ofl->ofl_tlsldgotndx)
		return (ofl->ofl_tlsldgotndx);

	for (ALIST_TRAVERSE(alp, idx, gnp)) {
		if ((rdesc->rel_raddend == gnp->gn_addend) &&
		    (gnp->gn_gotref == gref)) {
			return (gnp);
		}
	}
	return (NULL);
}


static Xword
ld_calc_got_offset(Rel_desc *rdesc, Ofl_desc *ofl)
{
	assert(0 && "ld_calc_got_offset");

	Os_desc		*osp = ofl->ofl_osgot;
	Sym_desc	*sdp = rdesc->rel_sym;
	Xword		gotndx;
	Gotref		gref;
	Gotndx		*gnp;

	if (rdesc->rel_flags & FLG_REL_DTLS)
		gref = GOT_REF_TLSGD;
	else if (rdesc->rel_flags & FLG_REL_MTLS)
		gref = GOT_REF_TLSLD;
	else if (rdesc->rel_flags & FLG_REL_STLS)
		gref = GOT_REF_TLSIE;
	else
		gref = GOT_REF_GENERIC;

	gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, rdesc);
	assert(gnp);

	gotndx = (Xword)gnp->gn_gotndx;

	if ((rdesc->rel_flags & FLG_REL_DTLS) &&
	    (rdesc->rel_rtype == R_AARCH64_TLS_DTPREL64)) /* XXX right reloc type? */
		gotndx++;

	return ((Xword)(osp->os_shdr->sh_addr + (gotndx * M_GOT_ENTSIZE)));
}

/*
 * Build a single PLT entry.  See the comment for ld_fillin_pltgot() for a
 * more complete description.
 */
/* ARGSUSED */
static void
plt_entry(Ofl_desc *ofl, Sym_desc *sdp)
{
	uchar_t	*pltent, *gotent;
	Word	plt_off;
	Word	got_off;
	Word	page_diff;
	Word 	page_offset;
	Boolean	bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;
	Addr	got_addr, plt_addr;

	got_off = sdp->sd_aux->sa_PLTGOTndx * M_GOT_ENTSIZE;
	plt_off = M_PLT_RESERVSZ + ((sdp->sd_aux->sa_PLTndx - 1) *
	    M_PLT_ENTSIZE);

	pltent = (uchar_t *)(ofl->ofl_osplt->os_outdata->d_buf) + plt_off;
	gotent = (uchar_t *)(ofl->ofl_osgot->os_outdata->d_buf) + got_off;

	got_addr = ofl->ofl_osgot->os_shdr->sh_addr + got_off;
	plt_addr = ofl->ofl_osplt->os_shdr->sh_addr + plt_off;
	page_diff = ((got_addr & ~0xfff) - (plt_addr & ~0xfff)) >> 12;
	page_offset = got_addr & 0xfff;

	/* LINTED */
	*(Word *)gotent = ofl->ofl_osplt->os_shdr->sh_addr;
	if (bswap)
		/* LINTED */
		*(Word *)gotent = ld_bswap_Word(*(Word *)gotent);

	// printf("Got off: 0x%x\nPlt off: 0x%x\nGot_addr: 0x%x\nPlt_addr: 0x%x\nGot_disp: 0x%x\n",
	    // got_off, plt_off, got_addr, plt_addr, got_disp);

	/* Encode the page difference into the ADRP instruction */
	/* LINTED */
	*(Word *)pltent = (0x90000010 | ((page_diff & 0x3) << 29) | ((page_diff & 0x1ffffc) << 3));
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);
	pltent += M_PLT_INSSIZE;

	/* ldr x17, [x16, #page_offset]*/
	/* LINTED */
	*(Word *)pltent = (0xf9400211 | ((page_offset >> 3) << 10));
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);
	pltent += M_PLT_INSSIZE;

	/* add x16, x16, #page_offset*/
	/* LINTED */
	*(Word *)pltent = (0x91000210 | (page_offset << 10));
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);
	pltent += M_PLT_INSSIZE;

	/* br x17*/
	/* LINTED */
	*(Word *)pltent = 0xd61f0220;
	if (bswap)
		/* LINTED */
		*(Word *)pltent = ld_bswap_Word(*(Word *)pltent);
	pltent += M_PLT_INSSIZE;
}


/* XXX: arm copies from x86_32 so copy from _64 */
static uintptr_t
ld_perform_outreloc(Rel_desc * orsp, Ofl_desc * ofl, Boolean *remain_seen)
{
	Os_desc *	relosp, * osp = 0;
	Word		ndx;
	Xword		roffset, value;
	Sxword		raddend;
	Rela		rea;
	char		*relbits;
	Sym_desc *	sdp, * psym = (Sym_desc *)0;
	int		sectmoved = 0;

	raddend = orsp->rel_raddend;
	sdp = orsp->rel_sym;

	/*
	 * If the section this relocation is against has been discarded
	 * (-zignore), then also discard (skip) the relocation itself.
	 */
	if (orsp->rel_isdesc && ((orsp->rel_flags &
	    (FLG_REL_GOT | FLG_REL_BSS | FLG_REL_PLT | FLG_REL_NOINFO)) == 0) &&
	    (orsp->rel_isdesc->is_flags & FLG_IS_DISCARD)) {
		DBG_CALL(Dbg_reloc_discard(ofl->ofl_lml, M_MACH, orsp));
		return (1);
	}

	/*
	 * If this is a relocation against a move table, or expanded move
	 * table, adjust the relocation entries.
	 */
	if (RELAUX_GET_MOVE(orsp))
		ld_adj_movereloc(ofl, orsp);

	/*
	 * If this is a relocation against a section then we need to adjust the
	 * raddend field to compensate for the new position of the input section
	 * within the new output section.
	 */
	if (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) {
		if (ofl->ofl_parsyms &&
		    (sdp->sd_isc->is_flags & FLG_IS_RELUPD) &&
		    /* LINTED */
		    (psym = ld_am_I_partial(orsp, orsp->rel_raddend))) {
			DBG_CALL(Dbg_move_outsctadj(ofl->ofl_lml, psym));
			sectmoved = 1;
			if (ofl->ofl_flags & FLG_OF_RELOBJ)
				raddend = psym->sd_sym->st_value;
			else
				raddend = psym->sd_sym->st_value -
				    psym->sd_isc->is_osdesc->os_shdr->sh_addr;
			/* LINTED */
			raddend += (Off)_elf_getxoff(psym->sd_isc->is_indata);
			if (psym->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
				raddend +=
				    psym->sd_isc->is_osdesc->os_shdr->sh_addr;
		} else {
			/* LINTED */
			raddend += (Off)_elf_getxoff(sdp->sd_isc->is_indata);
			if (sdp->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
				raddend +=
				    sdp->sd_isc->is_osdesc->os_shdr->sh_addr;
		}
	}

	value = sdp->sd_sym->st_value;

	if (orsp->rel_flags & FLG_REL_GOT) {
		/*
		 * Note: for GOT relative relocations on amd64
		 *	 we discard the addend.  It was relevant
		 *	 to the reference - not to the data item
		 *	 being referenced (ie: that -4 thing).
		 */
		raddend = 0;
		osp = ofl->ofl_osgot;
		roffset = ld_calc_got_offset(orsp, ofl);

	} else if (orsp->rel_flags & FLG_REL_PLT) {
		/*
		 * Note that relocations for PLT's actually
		 * cause a relocation againt the GOT.
		 */
		osp = ofl->ofl_osplt;
		roffset = (ofl->ofl_osgot->os_shdr->sh_addr) +
		    sdp->sd_aux->sa_PLTGOTndx * M_GOT_ENTSIZE;
		raddend = 0;
		/*if (*/plt_entry(ofl, sdp);/* == S_ERROR) XXX no idea*/
			// return (S_ERROR);

	} else if (orsp->rel_flags & FLG_REL_BSS) {
		/*
		 * This must be a R_AMD64_COPY.  For these set the roffset to
		 * point to the new symbols location.
		 */
		osp = ofl->ofl_isbss->is_osdesc;
		roffset = value;

		/*
		 * The raddend doesn't mean anything in a R_SPARC_COPY
		 * relocation.  Null it out because it can confuse people.
		 */
		raddend = 0;
	} else {
		osp = RELAUX_GET_OSDESC(orsp);

		/*
		 * Calculate virtual offset of reference point; equals offset
		 * into section + vaddr of section for loadable sections, or
		 * offset plus section displacement for nonloadable sections.
		 */
		roffset = orsp->rel_roffset +
		    (Off)_elf_getxoff(orsp->rel_isdesc->is_indata);
		if (!(ofl->ofl_flags & FLG_OF_RELOBJ))
			roffset += orsp->rel_isdesc->is_osdesc->
			    os_shdr->sh_addr;
	}

	if ((osp == 0) || ((relosp = osp->os_relosdesc) == 0))
		relosp = ofl->ofl_osrel;

	/*
	 * Assign the symbols index for the output relocation.  If the
	 * relocation refers to a SECTION symbol then it's index is based upon
	 * the output sections symbols index.  Otherwise the index can be
	 * derived from the symbols index itself.
	 */
	if (orsp->rel_rtype == R_AARCH64_RELATIVE)
		ndx = STN_UNDEF;
	else if ((orsp->rel_flags & FLG_REL_SCNNDX) ||
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION)) {
		if (sectmoved == 0) {
			/*
			 * Check for a null input section. This can
			 * occur if this relocation references a symbol
			 * generated by sym_add_sym().
			 */
			if (sdp->sd_isc && sdp->sd_isc->is_osdesc)
				ndx = sdp->sd_isc->is_osdesc->os_identndx;
			else
				ndx = sdp->sd_shndx;
		} else
			ndx = ofl->ofl_parexpnndx;
	} else
		ndx = sdp->sd_symndx;

	/*
	 * Add the symbols 'value' to the addend field.
	 */
	if (orsp->rel_flags & FLG_REL_ADVAL)
		raddend += value;


	//  * The addend field for R_AMD64_DTPMOD64 means nothing.  The addend
	//  * is propagated in the corresponding R_AMD64_DTPOFF64 relocation.
	///XXXaarch64 no idea
	if (orsp->rel_rtype == R_AARCH64_TLS_DTPMOD64)
		raddend = 0;

	relbits = (char *)relosp->os_outdata->d_buf;

	rea.r_info = ELF_R_INFO(ndx, orsp->rel_rtype);
	rea.r_offset = roffset;
	rea.r_addend = raddend;
	DBG_CALL(Dbg_reloc_out(ofl, ELF_DBG_LD, SHT_RELA, &rea, relosp->os_name,
	    ld_reloc_sym_name(orsp)));

	/*
	 * Assert we haven't walked off the end of our relocation table.
	 */
	assert(relosp->os_szoutrels <= relosp->os_shdr->sh_size);

	(void) memcpy((relbits + relosp->os_szoutrels),
	    (char *)&rea, sizeof (Rela));
	relosp->os_szoutrels += (Xword)sizeof (Rela);

	/*
	 * Determine if this relocation is against a non-writable, allocatable
	 * section.  If so we may need to provide a text relocation diagnostic.
	 * Note that relocations against the .plt (R_AMD64_JUMP_SLOT) actually
	 * result in modifications to the .got.
	 */
	if (orsp->rel_rtype == R_AARCH64_JUMP_SLOT)
		osp = ofl->ofl_osgot;

	ld_reloc_remain_entry(orsp, osp, ofl, remain_seen);
	return (1);
}

//XXXAARCH64 active relocs
static uintptr_t
ld_do_activerelocs(Ofl_desc *ofl)
{
	Rel_desc	*arsp;
	Rel_cachebuf	*rcbp;
	Aliste		idx;
	uintptr_t	return_code = 1;
	ofl_flag_t	flags = ofl->ofl_flags;

	if (aplist_nitems(ofl->ofl_actrels.rc_list) != 0)
		DBG_CALL(Dbg_reloc_doact_title(ofl->ofl_lml));

	/*
	 * Process active relocations.
	 */
	REL_CACHE_TRAVERSE(&ofl->ofl_actrels, idx, rcbp, arsp) {
		uchar_t		*addr;
		Xword 		value;
		Sym_desc	*sdp;
		const char	*ifl_name;
		Xword		refaddr;
		int		moved = 0;
		Gotref		gref;
		Os_desc		*osp;

		// printf("\n\nSymobl Info:\n");
		// printf("Section: %s, ", arsp->rel_isdesc->is_osdesc->os_name);
		// printf("Symbol: 0x%x, ", arsp->rel_sym);
		// printf("Offset: 0x%x, ", arsp->rel_roffset);
		// printf("Addend: 0x%x, ", arsp->rel_raddend);
		// printf("Flags: 0x%x, ", arsp->rel_flags);
		// printf("Type: %d\n", arsp->rel_rtype);
		// printf("Aux: 0x%x\n", arsp->rel_aux);

		// Sym_desc *sym = arsp->rel_sym;

		// printf("GOTndx: 0x%x, ", sym->sd_GOTndxs);
		// printf("Sym Table Entry: 0x%x, ", sym->sd_sym);
		// printf("Orig. Sym Entry: 0x%x, ", sym->sd_osym);
		// printf("Move Info: 0x%x, ", sym->sd_move);
		// printf("Name: %s, ", sym->sd_name);
		// printf("File: 0x%x, ", sym->sd_file);
		// printf("Input Sec: 0x%x, ", sym->sd_isc);
		// printf("Aux: 0x%x, ", sym->sd_aux);
		// printf("Sym Ndx: 0x%x, ", sym->sd_symndx);
		// printf("Shndx: 0x%x, ", sym->sd_shndx);
		// printf("Flags: 0x%x, ", sym->sd_flags);
		// printf("Ref: 0x%x\n", sym->sd_ref);

		// Os_desc	*ra_osdesc = RELAUX_GET_OSDESC(arsp);
		// Sym_desc *ra_usym = RELAUX_GET_USYM(arsp);
		// Mv_reloc *ra_mov = RELAUX_GET_MOVE(arsp);
		// Word ra_typedata = RELAUX_GET_TYPEDATA(arsp);

		// printf("Osdesc: 0x%x, ", ra_osdesc);
		// printf("Usym: 0x%x, ", ra_usym);
		// printf("Mov: 0x%x, ", ra_mov);
		// printf("Typedata: 0x%x\n", ra_typedata);

 		/*
		 * If the section this relocation is against has been discarded
		 * (-zignore), then discard (skip) the relocation itself.
		 */
		if ((arsp->rel_isdesc->is_flags & FLG_IS_DISCARD) &&
		    ((arsp->rel_flags & (FLG_REL_GOT | FLG_REL_BSS |
		    FLG_REL_PLT | FLG_REL_NOINFO)) == 0)) {
			DBG_CALL(Dbg_reloc_discard(ofl->ofl_lml, M_MACH, arsp));
			continue;
		}

		/*
		 * We determine what the 'got reference' model (if required)
		 * is at this point.  This needs to be done before tls_fixup()
		 * since it may 'transition' our instructions.
		 *
		 * The got table entries have already been assigned,
		 * and we bind to those initial entries.
		 */
		if (arsp->rel_flags & FLG_REL_DTLS)
			gref = GOT_REF_TLSGD;
		else if (arsp->rel_flags & FLG_REL_MTLS)
			gref = GOT_REF_TLSLD;
		else if (arsp->rel_flags & FLG_REL_STLS)
			gref = GOT_REF_TLSIE;
		else
			gref = GOT_REF_GENERIC;

		/*
		 * Perform any required TLS fixups.
		 */
		if (arsp->rel_flags & FLG_REL_TLSFIX) {
				//XXXaarch64 todo
			assert(0 && "Relocation claiming to need TLS fixups");
		}

		/*
		 * If this is a relocation against a move table, or
		 * expanded move table, adjust the relocation entries.
		 */
		if (RELAUX_GET_MOVE(arsp))
			ld_adj_movereloc(ofl, arsp);

		sdp = arsp->rel_sym;
		refaddr = arsp->rel_roffset +
		    (Off)_elf_getxoff(arsp->rel_isdesc->is_indata);

		if ((arsp->rel_flags & FLG_REL_CLVAL) ||
		    (arsp->rel_flags & FLG_REL_GOTCL))
			value = 0;
		else if (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION) {
			Sym_desc	*sym;
			/*
			 * The value for a symbol pointing to a SECTION
			 * is based off of that sections position.
			 */
			if ((sdp->sd_isc->is_flags & FLG_IS_RELUPD) &&
			    /* LINTED */
			    (sym = ld_am_I_partial(arsp, arsp->rel_raddend))) {
				/*
				 * The symbol was moved, so adjust the value
				 * relative to the new section.
				 */
				value = sym->sd_sym->st_value;
				moved = 1;

				/*
				 * The original raddend covers the displacement
				 * from the section start to the desired
				 * address. The value computed above gets us
				 * from the section start to the start of the
				 * symbol range. Adjust the old raddend to
				 * remove the offset from section start to
				 * symbol start, leaving the displacement
				 * within the range of the symbol.
				 */
				arsp->rel_raddend -= sym->sd_osym->st_value;
			} else {
				value = _elf_getxoff(sdp->sd_isc->is_indata);
				if (sdp->sd_isc->is_shdr->sh_flags & SHF_ALLOC)
					value += sdp->sd_isc->is_osdesc->
					    os_shdr->sh_addr;
			}
			if (sdp->sd_isc->is_shdr->sh_flags & SHF_TLS)
				value -= ofl->ofl_tlsphdr->p_vaddr;

		} else if (IS_SIZE(arsp->rel_rtype)) {
			/*
			 * Size relocations require the symbols size.
			 */
			value = sdp->sd_sym->st_size;

		} else if ((sdp->sd_flags & FLG_SY_CAP) &&
		    sdp->sd_aux && sdp->sd_aux->sa_PLTndx) {
			/*
			 * If relocation is against a capabilities symbol, we
			 * need to jump to an associated PLT, so that at runtime
			 * ld.so.1 is involved to determine the best binding
			 * choice. Otherwise, the value is the symbols value.
			 */
			value = ld_calc_plt_addr(sdp, ofl);
		} else
			value = sdp->sd_sym->st_value;

		/*
		 * Relocation against the GLOBAL_OFFSET_TABLE.
		 */
		if ((arsp->rel_flags & FLG_REL_GOT) &&
		    !ld_reloc_set_aux_osdesc(ofl, arsp, ofl->ofl_osgot))
			return (S_ERROR);
		osp = RELAUX_GET_OSDESC(arsp);

		/*
		 * If loadable and not producing a relocatable object add the
		 * sections virtual address to the reference address.
		 */
		if ((arsp->rel_flags & FLG_REL_LOAD) &&
		    ((flags & FLG_OF_RELOBJ) == 0))
			refaddr += arsp->rel_isdesc->is_osdesc->
			    os_shdr->sh_addr;

		/*
		 * If this entry has a PLT assigned to it, its value is actually
		 * the address of the PLT (and not the address of the function).
		 */
		if (IS_PLT(arsp->rel_rtype)) {
			if (sdp->sd_aux && sdp->sd_aux->sa_PLTndx)
				value = ld_calc_plt_addr(sdp, ofl);
		}

		/*
		 * Add relocations addend to value.  Add extra
		 * relocation addend if needed.
		 *
		 * Note: For GOT relative relocations on amd64 we discard the
		 * addend.  It was relevant to the reference - not to the
		 * data item being referenced (ie: that -4 thing).
		 */
		if ((arsp->rel_flags & FLG_REL_GOT) == 0)
			value += arsp->rel_raddend;

		/*
		 * Determine whether the value needs further adjustment. Filter
		 * through the attributes of the relocation to determine what
		 * adjustment is required.  Note, many of the following cases
		 * are only applicable when a .got is present.  As a .got is
		 * not generated when a relocatable object is being built,
		 * any adjustments that require a .got need to be skipped.
		 */
		if ((arsp->rel_flags & FLG_REL_GOT) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Xword		R1addr;
			uintptr_t	R2addr;
			Word		gotndx;
			Gotndx		*gnp;

			/*
			 * Perform relocation against GOT table. Since this
			 * doesn't fit exactly into a relocation we place the
			 * appropriate byte in the GOT directly
			 *
			 * Calculate offset into GOT at which to apply
			 * the relocation.
			 */
			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);

			if (arsp->rel_rtype == R_AMD64_DTPOFF64)
				gotndx = gnp->gn_gotndx + 1;
			else
				gotndx = gnp->gn_gotndx;

			R1addr = (Xword)(gotndx * M_GOT_ENTSIZE);

			/*
			 * Add the GOTs data's offset.
			 */
			R2addr = R1addr + (uintptr_t)osp->os_outdata->d_buf;

			DBG_CALL(Dbg_reloc_doact(ofl->ofl_lml, ELF_DBG_LD_ACT,
			    M_MACH, SHT_RELA, arsp, R1addr, value,
			    ld_reloc_sym_name));

			/*
			 * And do it.
			 */
			if (ofl->ofl_flags1 & FLG_OF1_ENCDIFF)
				*(Xword *)R2addr = ld_bswap_Xword(value);
			else
				*(Xword *)R2addr = value;


			printf("R1addr, R2addr: 0x%x, 0x%x\n", R1addr, value);
			continue;
		}

		if (IS_GOT_RELATIVE(arsp->rel_rtype) &&
			((flags & FLG_OF_RELOBJ) == 0)) {

			Gotndx *gnp;
			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);
			value = (Xword)gnp->gn_gotndx * M_GOT_ENTSIZE;

			value += ofl->ofl_osgot->os_shdr->sh_addr;
		}

		if (IS_GOT_BASED(arsp->rel_rtype) &&
			((flags & FLG_OF_RELOBJ) == 0)) {

			if (IS_GOTPAGE_RELATIVE(arsp->rel_rtype)) {
				value -= (ofl->ofl_osgot->os_shdr->sh_addr & ~0xfff);
			} else {
				value -= ofl->ofl_osgot->os_shdr->sh_addr;
			}
		} else if (IS_GOTPCREL(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Gotndx *gnp;

			assert(0 && "haven't thought about this yet1");

			/*
			 * Calculation:
			 *	G + GOT + A - P
			 */
			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);
			value = (Xword)(ofl->ofl_osgot->os_shdr-> sh_addr) +
			    ((Xword)gnp->gn_gotndx * M_GOT_ENTSIZE) +
			    arsp->rel_raddend - refaddr;

		} else if ((IS_PC_RELATIVE(arsp->rel_rtype)) &&
		    (((flags & FLG_OF_RELOBJ) == 0) ||
		    (osp == sdp->sd_isc->is_osdesc))) {

		    	if (IS_PCPAGE_RELATIVE(arsp->rel_rtype)) {
				value -= (refaddr & ~0xfff);
		    	} else {
				value -= refaddr;
		    	}

		} else if (IS_TLS_INS(arsp->rel_rtype) &&
		    IS_GOT_RELATIVE(arsp->rel_rtype) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {

			assert(0 && "haven't thought about this yet2");
			Gotndx	*gnp;

			gnp = ld_find_got_ndx(sdp->sd_GOTndxs, gref, ofl, arsp);
			assert(gnp);
			value = (Xword)gnp->gn_gotndx * M_GOT_ENTSIZE;

		} else if ((arsp->rel_flags & FLG_REL_STLS) &&
		    ((flags & FLG_OF_RELOBJ) == 0)) {
			Xword	tlsstatsize;

			assert(0 && "haven't thought about this yet3");
			/*
			 * This is the LE TLS reference model.  Static
			 * offset is hard-coded.
			 */
			tlsstatsize = S_ROUND(ofl->ofl_tlsphdr->p_memsz,
			    M_TLSSTATALIGN);
			value = tlsstatsize - value;

			/*
			 * Since this code is fixed up, it assumes a negative
			 * offset that can be added to the thread pointer.
			 */
			if (arsp->rel_rtype == R_AMD64_TPOFF32)
				value = -value;
		}

		if (arsp->rel_isdesc->is_file)
			ifl_name = arsp->rel_isdesc->is_file->ifl_name;
		else
			ifl_name = MSG_INTL(MSG_STR_NULL);

		/*
		 * Make sure we have data to relocate.  Compiler and assembler
		 * developers have been known to generate relocations against
		 * invalid sections (normally .bss), so for their benefit give
		 * them sufficient information to help analyze the problem.
		 * End users should never see this.
		 */
		if (arsp->rel_isdesc->is_indata->d_buf == 0) {
			Conv_inv_buf_t inv_buf;

			ld_eprintf(ofl, ERR_FATAL, MSG_INTL(MSG_REL_EMPTYSEC),
			    conv_reloc_amd64_type(arsp->rel_rtype, 0, &inv_buf),
			    ifl_name, ld_reloc_sym_name(arsp),
			    EC_WORD(arsp->rel_isdesc->is_scnndx),
			    arsp->rel_isdesc->is_name);
			return (S_ERROR);
		}

		/*
		 * Get the address of the data item we need to modify.
		 */
		addr = (uchar_t *)((uintptr_t)arsp->rel_roffset +
		    (uintptr_t)_elf_getxoff(arsp->rel_isdesc->is_indata));

		DBG_CALL(Dbg_reloc_doact(ofl->ofl_lml, ELF_DBG_LD_ACT,
		    M_MACH, SHT_RELA, arsp, EC_NATPTR(addr), value,
		    ld_reloc_sym_name));
		addr += (uintptr_t)osp->os_outdata->d_buf;

		if ((((uintptr_t)addr - (uintptr_t)ofl->ofl_nehdr) >
		    ofl->ofl_size) || (arsp->rel_roffset >
		    osp->os_shdr->sh_size)) {
			int		class;
			Conv_inv_buf_t inv_buf;

			if (((uintptr_t)addr - (uintptr_t)ofl->ofl_nehdr) >
			    ofl->ofl_size)
				class = ERR_FATAL;
			else
				class = ERR_WARNING;

			ld_eprintf(ofl, class, MSG_INTL(MSG_REL_INVALOFFSET),
			    conv_reloc_amd64_type(arsp->rel_rtype, 0, &inv_buf),
			    ifl_name, EC_WORD(arsp->rel_isdesc->is_scnndx),
			    arsp->rel_isdesc->is_name, ld_reloc_sym_name(arsp),
			    EC_ADDR((uintptr_t)addr -
			    (uintptr_t)ofl->ofl_nehdr));

			if (class == ERR_FATAL) {
				return_code = S_ERROR;
				continue;
			}
		}

		/*
		 * The relocation is additive.  Ignore the previous symbol
		 * value if this local partial symbol is expanded.
		 */
		if (moved)
			value -= *addr;

		/*
		 * If '-z noreloc' is specified - skip the do_reloc_ld stage.
		 */
		if (OFL_DO_RELOC(ofl)) {
			/*
			 * If this is a PROGBITS section and the running linker
			 * has a different byte order than the target host,
			 * tell do_reloc_ld() to swap bytes.
			 */
			if (do_reloc_ld(arsp, addr, &value, ld_reloc_sym_name,
			    ifl_name, OFL_SWAP_RELOC_DATA(ofl, arsp),
			    ofl->ofl_lml) == 0) {
				ofl->ofl_flags |= FLG_OF_FATAL;
				return_code = S_ERROR;
			}
		}
	}
	return (return_code);
}

/*
 * XXXAARCh64: copied from toher implmentations, seems to be not target specific
 */
static uintptr_t
ld_add_outrel(Word flags, Rel_desc *rsp, Ofl_desc *ofl)
{
	Rel_desc	*orsp;
	Sym_desc	*sdp = rsp->rel_sym;

	/*
	 * Static executables *do not* want any relocations against them.
	 * Since our engine still creates relocations against a WEAK UNDEFINED
	 * symbol in a static executable, it's best to disable them here
	 * instead of through out the relocation code.
	 */
	if (OFL_IS_STATIC_EXEC(ofl))
		return (1);

	/*
	 * If we are adding a output relocation against a section
	 * symbol (non-RELATIVE) then mark that section.  These sections
	 * will be added to the .dynsym symbol table.
	 */
	if (sdp && (rsp->rel_rtype != M_R_RELATIVE) &&
	    ((flags & FLG_REL_SCNNDX) ||
	    (ELF_ST_TYPE(sdp->sd_sym->st_info) == STT_SECTION))) {

		/*
		 * If this is a COMMON symbol - no output section
		 * exists yet - (it's created as part of sym_validate()).
		 * So - we mark here that when it's created it should
		 * be tagged with the FLG_OS_OUTREL flag.
		 */
		if ((sdp->sd_flags & FLG_SY_SPECSEC) &&
		    (sdp->sd_sym->st_shndx == SHN_COMMON)) {
			if (ELF_ST_TYPE(sdp->sd_sym->st_info) != STT_TLS)
				ofl->ofl_flags1 |= FLG_OF1_BSSOREL;
			else
				ofl->ofl_flags1 |= FLG_OF1_TLSOREL;
		} else {
			Os_desc *osp;
			Is_desc *isp = sdp->sd_isc;

			if (isp && ((osp = isp->is_osdesc) != NULL) &&
			    ((osp->os_flags & FLG_OS_OUTREL) == 0)) {
				ofl->ofl_dynshdrcnt++;
				osp->os_flags |= FLG_OS_OUTREL;
			}
		}
	}

	/* Enter it into the output relocation cache */
	if ((orsp = ld_reloc_enter(ofl, &ofl->ofl_outrels, rsp, flags)) == NULL)
		return (S_ERROR);

	if (flags & FLG_REL_GOT)
		ofl->ofl_relocgotsz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_PLT)
		ofl->ofl_relocpltsz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_BSS)
		ofl->ofl_relocbsssz += (Xword)sizeof (Rela);
	else if (flags & FLG_REL_NOINFO)
		ofl->ofl_relocrelsz += (Xword)sizeof (Rela);
	else
		RELAUX_GET_OSDESC(orsp)->os_szoutrels += (Xword)sizeof (Rela);

	if (orsp->rel_rtype == M_R_RELATIVE)
		ofl->ofl_relocrelcnt++;

	/*
	 * We don't perform sorting on PLT relocations because
	 * they have already been assigned a PLT index and if we
	 * were to sort them we would have to re-assign the plt indexes.
	 */
	if (!(flags & FLG_REL_PLT))
		ofl->ofl_reloccnt++;

	/*
	 * Insure a GLOBAL_OFFSET_TABLE is generated if required.
	 */
	if (IS_GOT_REQUIRED(orsp->rel_rtype))
		ofl->ofl_flags |= FLG_OF_BLDGOT;

	/*
	 * Identify and possibly warn of a displacement relocation.
	 */
	if (orsp->rel_flags & FLG_REL_DISP) {
		ofl->ofl_dtflags_1 |= DF_1_DISPRELPND;

		if (ofl->ofl_flags & FLG_OF_VERBOSE)
			ld_disp_errmsg(MSG_INTL(MSG_REL_DISPREL4), orsp, ofl);
	}
	DBG_CALL(Dbg_reloc_ors_entry(ofl->ofl_lml, ELF_DBG_LD, SHT_RELA,
	    M_MACH, orsp));
	return (1);
}


/*
 * Deal with relocations against symbols which are bound locally, as described
 * ld_process_sym_reloc()
 *
 * Symbols which must be bound locally need to be treated specially to make
 * sure that they, post-relocation, actually do refer to their locally
 * appropriate values.  In most cases we end up doing this with an active
 * relocation resolved during the link-edit, if that for some reason can't be
 * done, we emit R_ARM_RELATIVE to ensure we reach the right symbol.
 *
 * XXXARM: The implementation here is, again, a carbon copy of the intel
 * implementation, which is an almost copy of the SPARC implementation (where
 * more relocations avoid R_..._RELATIVE).
 */
static uintptr_t
ld_reloc_local(Rel_desc * rsp, Ofl_desc * ofl)
{
	ofl_flag_t	flags = ofl->ofl_flags;
	Sym_desc	*sdp = rsp->rel_sym;
	Word		shndx = sdp->sd_sym->st_shndx;

	/*
	 * if ((shared object) and (not pc relative relocation) and
	 *    (not against ABS symbol))
	 * then
	 *    build R_ARM_RELATIVE
	 * fi
	 */
	if ((flags & FLG_OF_SHAROBJ) && (rsp->rel_flags & FLG_REL_LOAD) &&
	    !(IS_PC_RELATIVE(rsp->rel_rtype)) && !(IS_SIZE(rsp->rel_rtype)) &&
	    !(IS_GOT_BASED(rsp->rel_rtype)) &&
	    !(rsp->rel_isdesc != NULL &&
	    (rsp->rel_isdesc->is_shdr->sh_type == SHT_SUNW_dof)) &&
	    (((sdp->sd_flags & FLG_SY_SPECSEC) == 0) ||
	    (shndx != SHN_ABS) || (sdp->sd_aux && sdp->sd_aux->sa_symspec))) {
		Word	ortype = rsp->rel_rtype;

		/*
		 * R_AARCH64_RELATIVE updates a 64bit address, if this
		 * relocation isn't a 64bit binding then we can not
		 * simplify it to a RELATIVE relocation.
		 */
		if (reloc_table[ortype].re_fsize != sizeof (Addr)) {
			return (ld_add_outrel(0, rsp, ofl));
		}

		rsp->rel_rtype = R_AARCH64_RELATIVE;
		if (ld_add_outrel(NULL, rsp, ofl) == S_ERROR)
			return (S_ERROR);
		rsp->rel_rtype = ortype;
		return (1);
	}

	/*
	 * If the relocation is against a 'non-allocatable' section
	 * and we can not resolve it now - then give a warning
	 * message.
	 *
	 * We can not resolve the symbol if either:
	 *	a) it's undefined
	 *	b) it's defined in a shared library and a
	 *	   COPY relocation hasn't moved it to the executable
	 *
	 * Note: because we process all of the relocations against the
	 *	text segment before any others - we know whether
	 *	or not a copy relocation will be generated before
	 *	we get here (see reloc_init()->reloc_segments()).
	 */
	if (!(rsp->rel_flags & FLG_REL_LOAD) &&
	    ((shndx == SHN_UNDEF) ||
	    ((sdp->sd_ref == REF_DYN_NEED) &&
	    ((sdp->sd_flags & FLG_SY_MVTOCOMM) == 0)))) {
		Conv_inv_buf_t	inv_buf;
		Os_desc		*osp = RELAUX_GET_OSDESC(rsp);

		/*
		 * If the relocation is against a SHT_SUNW_ANNOTATE
		 * section - then silently ignore that the relocation
		 * can not be resolved.
		 */
		if ((osp != NULL) && (osp->os_shdr->sh_type ==
		    SHT_SUNW_ANNOTATE))
			return (0);

		ld_eprintf(ofl, ERR_WARNING, MSG_INTL(MSG_REL_EXTERNSYM),
		    conv_reloc_amd64_type(rsp->rel_rtype, 0, &inv_buf),
		    rsp->rel_isdesc->is_file->ifl_name,
		    ld_reloc_sym_name(rsp), osp->os_name);
		return (1);
	}

	/*
	 * Perform relocation.
	 */
	return (ld_add_actrel(NULL, rsp, ofl));
}


/* ARGSUSED */
static uintptr_t
ld_reloc_GOTOP(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	assert(0 && "ld_reloc_GOTOP");
	return (0);
}

/* ARGSUSED */
static uintptr_t
ld_reloc_TLS(Boolean local, Rel_desc *rsp, Ofl_desc *ofl)
{
	assert(0 && "ld_reloc_TLS");
	return (0);
}

/*
 * XXXARM: This is taken directly from the x86_64 version...
 */
/* ARGSUSED5 */
static uintptr_t
ld_assign_got_ndx(Alist **alpp, Gotndx *pgnp, Gotref gref, Ofl_desc *ofl,
    Rel_desc *rsp, Sym_desc *sdp)
{
	Xword		raddend;
	Gotndx		gn, *gnp;
	Aliste		idx;
	uint_t		gotents;

	raddend = rsp->rel_raddend;
	if (pgnp && (pgnp->gn_addend == raddend) && (pgnp->gn_gotref == gref))
		return (1);

	if ((gref == GOT_REF_TLSGD) || (gref == GOT_REF_TLSLD))
		gotents = 2;
	else
		gotents = 1;

	gn.gn_addend = raddend;
	gn.gn_gotndx = ofl->ofl_gotcnt;
	gn.gn_gotref = gref;

	ofl->ofl_gotcnt += gotents;

	if (gref == GOT_REF_TLSLD) {
		if (ofl->ofl_tlsldgotndx == NULL) {
			if ((gnp = libld_malloc(sizeof (Gotndx))) == NULL)
				return (S_ERROR);
			(void) memcpy(gnp, &gn, sizeof (Gotndx));
			ofl->ofl_tlsldgotndx = gnp;
		}
		return (1);
	}

	idx = 0;
	for (ALIST_TRAVERSE(*alpp, idx, gnp)) {
		if (gnp->gn_addend > raddend)
			break;
	}

	/*
	 * GOT indexes are maintained on an Alist, where there is typically
	 * only one index.  The usage of this list is to scan the list to find
	 * an index, and then apply that index immediately to a relocation.
	 * Thus there are no external references to these GOT index structures
	 * that can be compromised by the Alist being reallocated.
	 */
	if (alist_insert(alpp, &gn, sizeof (Gotndx),
	    AL_CNT_SDP_GOT, idx) == NULL)
		return (S_ERROR);

	return (1);
}

/* XXXARCH64: every arch does this same way */
static void
ld_assign_plt_ndx(Sym_desc * sdp, Ofl_desc *ofl)
{
	sdp->sd_aux->sa_PLTndx = 1 + ofl->ofl_pltcnt++;
	sdp->sd_aux->sa_PLTGOTndx = ofl->ofl_gotcnt++;
	ofl->ofl_flags |= FLG_OF_BLDGOT;
}

/*
 * Each PLT entry after 0 is set up as follows:
 *
 * .PLT[i]:
 *	adrp	x16, GOT[i]
 *	ldr	x17, [x16, (GOT[i] & 0xfff)]
 *	add	x16, x16, #(GOT[i] & 0xfff)
 *	br	x17
 *
 * Which first puts into x16 the address of the GOT entry we're loading from,
 * and loads into x17 the correspending entry.
 * This then branches into x17.
 *
 * The entry starts as a pointer to PLT[0], filled in in this function as:
 *
 * .PLT[0]:
 *	stp	x16, x30, [sp,#-16]!
 *	adrp	x16, GOT[2]
 *	ldr	x17, [x16, (GOT[2] & 0xfff)]
 *	add	x16, x16, #(GOT[2] & 0xfff)
 *	br	x17
 *
 * This stores x16 (along with the link register, x30), which from PLT[i]
 * contains a pointer to the GOT entry we are going to modify. Next, via x16
 * we load into x17 the entry at GOT[2], containing a pointer to the rtbinder.
 * We then branch to this address.
 *
 * Thus, calling 'foo' will:
 *	1. execute it's PLT entry, loading the address of its GOT entry in x16
 *	2. jump to plt[0]
 *	3. plt[0] jumps to elf_rtbinder (without losing the GOT address)
 * 	4. elf_rtbinder stores the address of foo in the GOT entry + calls foo
 *
 * So, all future calls to foo will execute the PLT entry, which will load
 * it's GOT entry and jump to the function instead of PLT[0].
 */
static uintptr_t
ld_fillin_gotplt(Ofl_desc *ofl)
{
	ofl_flag_t	flags = ofl->ofl_flags;
	int		bswap = (ofl->ofl_flags1 & FLG_OF1_ENCDIFF) != 0;

	if (ofl->ofl_osgot) {
		Sym_desc	*sdp;

		if ((sdp = ld_sym_find(MSG_ORIG(MSG_SYM_DYNAMIC_U),
		    SYM_NOHASH, NULL, ofl)) != NULL) {
			uchar_t	*genptr;

			genptr = ((uchar_t *)ofl->ofl_osgot->os_outdata->d_buf +
			    (M_GOT_XDYNAMIC * M_GOT_ENTSIZE));
			/* LINTED */
			*(Word *)genptr = (Word)sdp->sd_sym->st_value;
			if (bswap)
				/* LINTED */
				*(Word *)genptr =
				    /* LINTED */
				    ld_bswap_Word(*(Word *)genptr);
		}
	}

	if ((flags & FLG_OF_DYNAMIC) && (ofl->ofl_osplt != NULL)) {

		int i;
		uchar_t *plt0 = (uchar_t *)ofl->ofl_osplt->os_outdata->d_buf;
		static uint32_t entry[] = {
			0xa9bf7bf0, /* stp x16, x30, [sp,#-16]! */
			0x90000010, /* adrp x16, GOT[2] */
			0xf9400211, /* ldr x17, [x16, (GOT[2] & 0xfff)] */
			0x91000210, /* add x16, x16, (GOT[2] & 0xfff) */
			0xd61f0220, /* br x17  branch */
		};

		/* Get the address of the rt bindr */
		Addr binder_got_addr = ofl->ofl_osgot->os_shdr->sh_addr + (M_GOT_ENTSIZE * M_GOT_XRTLD);
		/* get the address of this instruction (instruction 2 in the plt) */
		Addr instr_addr = ofl->ofl_osplt->os_shdr->sh_addr + 0x4;
		/* Calculate page offset to encode */
		Addr page_diff = ((binder_got_addr & ~0xfff) - (instr_addr & ~0xfff)) >> 12;
		/* Encode entry[1] to adrp x16, Page(GOT[2]) */
		entry[1] |= ((page_diff & 0x3) << 29) | ((page_diff & 0x1ffffc) << 3);

		Addr binder_nonpage_off = binder_got_addr & 0xfff;
		entry[2] |= ((binder_nonpage_off >> 3) << 10); /* divide by 8 then encode to immediate field */

		entry[3] |= (binder_nonpage_off << 10); /* encode to imm field */

		for (i = 0; i < 5; i++, plt0 += M_PLT_INSSIZE) {
			/* LINTED */
			*(Word *)plt0 = entry[i];
			if (bswap)
				/* LINTED */
				*(Word *)plt0 = ld_bswap_Word(*(Word *)plt0);
		}
	}

	return (1);
}

/* void (*)(void) function */
static const uchar_t nullfunc_tmpl[] = {
	/* XXXAARRCH64: check this*/
	/* Prologue: */
	/* Store FP (x29) and LR (x30) on the stack, moving sp -16 with them */
	0xfd, 0x7b, 0xbf, 0xa9, /* stp x29, x30, [sp,#-16]! */
	/* Put the current SP value into the FP */
	0xfd, 0x03, 0x00, 0x91,	/* mov x29, sp */

	/* Epilogue: */
	/*
	 * Load from SP (where the frame pointer was) the prev FP and LR,
	 * moving sp back up 16 (restoring its position)
	 */
	0xfd, 0x7b, 0xc1, 0xa8, /* ldp x29, x30, [sp], #16 */
	/* Return (aka jump to x30 (the LR)) */
	0xc0, 0x03, 0x5f, 0xd6, /* ret */
};

const Target *
ld_targ_init_arm(void)
{
	static const Target _ld_targ = {
		.t_m = {
			.m_mach			= M_MACH,
			.m_machplus		= M_MACHPLUS,
			.m_flagsplus		= M_FLAGSPLUS,
			.m_class		= M_CLASS,
			.m_data			= M_DATA,

			.m_segm_align		= M_SEGM_ALIGN,
			.m_segm_origin		= M_SEGM_ORIGIN,
			.m_segm_aorigin		= M_SEGM_AORIGIN,
			.m_dataseg_perm		= M_DATASEG_PERM,
			.m_stack_perm		= M_STACK_PERM,
			.m_word_align		= M_WORD_ALIGN,
			.m_def_interp		= MSG_ORIG(MSG_PTH_RTLD),

			.m_r_arrayaddr		= M_R_ARRAYADDR,
			.m_r_copy		= M_R_COPY,
			.m_r_glob_dat		= M_R_GLOB_DAT,
			.m_r_jmp_slot		= M_R_JMP_SLOT,
			.m_r_num		= M_R_NUM,
			.m_r_none		= M_R_NONE,
			.m_r_relative		= M_R_RELATIVE,
			.m_r_register		= M_R_REGISTER,

			.m_rel_dt_count		= M_REL_DT_COUNT,
			.m_rel_dt_ent		= M_REL_DT_ENT,
			.m_rel_dt_size		= M_REL_DT_SIZE,
			.m_rel_dt_type		= M_REL_DT_TYPE,
			.m_rel_sht_type		= M_REL_SHT_TYPE,

			.m_got_entsize		= M_GOT_ENTSIZE,
			.m_got_xnumber		= M_GOT_XNumber,

			.m_plt_align		= M_PLT_ALIGN,
			.m_plt_entsize		= M_PLT_ENTSIZE,
			.m_plt_reservsz		= M_PLT_RESERVSZ,
			.m_plt_shf_flags	= M_PLT_SHF_FLAGS,

			.m_sht_unwind		= SHT_PROGBITS,

			.m_dt_register		= M_DT_REGISTER
		},
		.t_id = {
			.id_array	= M_ID_ARRAY,
			.id_bss		= M_ID_BSS,
			.id_cap		= M_ID_CAP,
			.id_capinfo	= M_ID_CAPINFO,
			.id_capchain	= M_ID_CAPCHAIN,
			.id_data	= M_ID_DATA,
			.id_dynamic	= M_ID_DYNAMIC,
			.id_dynsort	= M_ID_DYNSORT,
			.id_dynstr	= M_ID_DYNSTR,
			.id_dynsym	= M_ID_DYNSYM,
			.id_dynsym_ndx	= M_ID_DYNSYM_NDX,
			.id_got		= M_ID_GOT,
			.id_gotdata	= M_ID_UNKNOWN,
			.id_hash	= M_ID_HASH,
			.id_interp	= M_ID_INTERP,
			.id_lbss	= M_ID_UNKNOWN,
			.id_ldynsym	= M_ID_LDYNSYM,
			.id_note	= M_ID_NOTE,
			.id_null	= M_ID_NULL,
			.id_plt		= M_ID_PLT,
			.id_rel		= M_ID_REL,
			.id_strtab	= M_ID_STRTAB,
			.id_syminfo	= M_ID_SYMINFO,
			.id_symtab	= M_ID_SYMTAB,
			.id_symtab_ndx	= M_ID_SYMTAB_NDX,
			.id_text	= M_ID_TEXT,
			.id_tls		= M_ID_TLS,
			.id_tlsbss	= M_ID_TLSBSS,
			.id_unknown	= M_ID_UNKNOWN,
			.id_unwind	= M_ID_UNWIND,
			.id_unwindhdr	= M_ID_UNWINDHDR,
			.id_user	= M_ID_USER,
			.id_version	= M_ID_VERSION,
		},
		.t_nf = {
			.nf_template	= nullfunc_tmpl,
			.nf_size	= sizeof (nullfunc_tmpl),
		},
		.t_ff = {
			/*
			 * XXXAARCH64: Marking this as null will use 0x0 to fill
			 * 0x0 is an invalid instruction, but it seems like
			 * SPARC does the same and is fine... Worst case this is
			 * an issue and we get illegal instructions running, and
			 * we have to implement this
			 */
			.ff_execfill	= NULL,
		},
		.t_mr = {
			.mr_reloc_table			= reloc_table,
			.mr_init_rel			= ld_init_rel,
			.mr_mach_eflags			= ld_mach_eflags,
			.mr_mach_make_dynamic		= ld_mach_make_dynamic,
			.mr_mach_update_odynamic	= ld_mach_update_odynamic,
			.mr_calc_plt_addr		= ld_calc_plt_addr,
			.mr_perform_outreloc		= ld_perform_outreloc,
			.mr_do_activerelocs		= ld_do_activerelocs,
			.mr_add_outrel			= ld_add_outrel,
			.mr_reloc_register		= NULL,
			.mr_reloc_local			= ld_reloc_local,
			.mr_reloc_GOTOP			= ld_reloc_GOTOP,
			.mr_reloc_TLS			= ld_reloc_TLS,
			.mr_assign_got			= NULL,
			.mr_find_got_ndx		= ld_find_got_ndx,
			.mr_calc_got_offset		= ld_calc_got_offset,
			.mr_assign_got_ndx		= ld_assign_got_ndx,
			.mr_assign_plt_ndx		= ld_assign_plt_ndx,
			.mr_allocate_got		= NULL,
			.mr_fillin_gotplt		= ld_fillin_gotplt,
		},
		.t_ms = {
			.ms_reg_check		= NULL,
			.ms_mach_sym_typecheck	= NULL,
			.ms_is_regsym		= NULL,
			.ms_reg_find		= NULL,
			.ms_reg_enter		= NULL,
		}
	};

	return (&_ld_targ);
}