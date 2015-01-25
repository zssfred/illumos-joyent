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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * Fake stubs that we need to advance
 */
extern void bop_panic(const char *);

#define	STUB(x) void x(void) { bop_panic(#x); }

STUB(bcmp)
STUB(kdi_flush_caches)
STUB(kobj_text_alloc)
STUB(kdi_range_is_nontoxic)
STUB(dcache_flushall)
STUB(SHA1Final)
STUB(kdi_pwrite)
STUB(SHA1Update)
STUB(hat_unload)
STUB(stubs_base)
STUB(rw_exit)
STUB(hat_getpfnum)
STUB(hat_devload)
STUB(kdi_vtop)
STUB(stubs_end)
STUB(SHA1Init)
STUB(rw_enter)
STUB(kobj_texthole_free)
STUB(kdi_pread)
STUB(kobj_vmem_init)
STUB(cpr)
STUB(acct)
STUB(bind)
STUB(recv)
STUB(send)
STUB(spl0)
STUB(spl7)
STUB(spl8)
STUB(splx)
STUB(audit_init_module)
STUB(i_ddi_intr_ops)
STUB(dcopy_cmd_alloc)
STUB(impl_acc_hdl_free)
STUB(plat_hold_page)
STUB(check_status)
STUB(audit_symlink_create)
STUB(hat_page_clrattr)
STUB(copyinstr_noerr)
STUB(audit)
STUB(cas32)
STUB(cas64)
STUB(copyoutstr)
STUB(getfp)
STUB(htonl)
STUB(htons)
STUB(indir)
STUB(idmap_reg_dh)
STUB(kcopy)
STUB(kzero)
STUB(nosys)
STUB(ntohl)
STUB(ntohs)
STUB(fifo_vfastoff)
STUB(splhi)
STUB(ucopy)
STUB(uzero)
STUB(i_ddi_acc_clr_fault)
STUB(audit_setf)
STUB(audit_priv)
STUB(audit_exec)
STUB(audit_exit)
STUB(hat_leave_region)
STUB(door_ki_upcall)
STUB(unset_idle_cpu)
STUB(thread_onproc)
STUB(set_proc_ast)
STUB(ddi_rep_put64)
STUB(ddi_rep_put32)
STUB(ddi_rep_put16)
STUB(boot_virt_alloc)
STUB(ddi_rep_get64)
STUB(ddi_rep_get32)
STUB(ddi_rep_get16)
STUB(i_ddi_map_fault)
STUB(lwp_stk_cache_init)
STUB(dtrace_interrupt_enable)
STUB(ftrace_interrupt_enable)
STUB(xcopyout_nta)
STUB(hat_pagesync)
STUB(console_enter)
STUB(spec_snode_walk)
STUB(audit_chdirec)
STUB(prinvalidate)
STUB(lock_clear)
STUB(ka_init)
STUB(loadable_syscall)
STUB(sockconfig)
STUB(fuword8_noerr)
STUB(lwp_detach_brand_hdlrs)
STUB(valid_va_range_aligned)
STUB(lwp_forkregs)
STUB(devfs_devpolicy)
STUB(hat_stats_disable)
STUB(pr_free_watched_pages)
STUB(install_utrap)
STUB(dtrace_membar_consumer)
STUB(socket_sendmblk)
STUB(audit_symlink)
STUB(i_ddi_apply_range)
STUB(lock_clear_splx)
STUB(audit_strputmsg)
STUB(i_ddi_alloc_intr_phdl)
STUB(i_ddi_acc_set_fault)
STUB(clconf_get_nodeid)
STUB(e_ddi_copyfromdev)
STUB(impl_acc_hdl_alloc)
STUB(sdev_devstate_change)
STUB(translate_devid)
STUB(impl_keep_instance)
STUB(hat_stats_enable)
STUB(hr_clock_unlock)
STUB(audit_closef)
STUB(hat_join_srd)
STUB(hat_softlock)
STUB(spec_is_clone)
STUB(audit_fdsend)
STUB(audit_fdrecv)
STUB(random_get_bytes)
STUB(audit_finish)
STUB(pf_is_memory)
STUB(peekpoke_mem)
STUB(fastboot_update_config)
STUB(audit_savepath)
STUB(hat_get_mapped_size)
STUB(thread_stk_init)
STUB(hat_free_start)
STUB(impl_ddi_sunbus_initchild)
STUB(lwp_rtt)
STUB(prlwpfree)
STUB(prlwpexit)
STUB(hat_memload)
STUB(console_exit)
STUB(map_addr_vacalign_check)
STUB(hat_pageunload)
STUB(spec_fence_snode)
STUB(copyout_noerr)
STUB(audit_vncreate_finish)
STUB(on_fault)
STUB(door_ki_lookup)
STUB(lbolt_softint_post)
STUB(door_revoke_all)
STUB(spec_is_selfclone)
STUB(prefetch_write_many)
STUB(dump_plat_addr)
STUB(dump_plat_data)
STUB(au_to_arg32)
STUB(random_get_pseudo_bytes)
STUB(num_phys_pages)
STUB(cmp_set_nosteal_interval)
STUB(no_fault)
STUB(sync_icache)
STUB(lock_try)
STUB(lock_set)
STUB(sock_getmsg)
STUB(getsetcontext)
STUB(i_ddi_rnumber_to_regspec)
STUB(lock_spin_try)
STUB(_insque)
STUB(sock_putmsg)
STUB(pr_isself)
STUB(save_syscall_args)
STUB(getsockname)
STUB(fss_allocbuf)
STUB(poke_cpu)
STUB(lbolt_softint_add)
STUB(on_trap)
STUB(ip_ocsum)
STUB(audit_vncreate_start)
STUB(i_ddi_free_intr_phdl)
STUB(accept)
STUB(kcopy_nta)
STUB(audit_devpolicy)
STUB(page_mem_avail)
STUB(door_exit)
STUB(door_fork)
STUB(door_slam)
STUB(_remque)
STUB(valid_usr_range)
STUB(i_ddi_bus_map)
STUB(caller)
STUB(casptr)
STUB(snf_segmap)
STUB(so_socket)
STUB(copyin)
STUB(socket_setsockopt)
STUB(getpcstack)
STUB(va_to_pfn)
STUB(specfind)
STUB(gethrestime_sec)
STUB(hat_unlock)
STUB(ovbcopy)
STUB(au_uwrite)
STUB(spec_segmap)
STUB(exec_set_sp)
STUB(copyin_noerr)
STUB(audit_setppriv)
STUB(listen)
STUB(lowbit)
STUB(mdboot)
STUB(door_ki_rele)
STUB(door_ki_hold)
STUB(door_ki_info)
STUB(door_ki_open)
STUB(i_ddi_add_softint)
STUB(prexit)
STUB(prfree)
STUB(prstep)
STUB(kpreempt)
STUB(mdpreboot)
STUB(resume)
STUB(hr_clock_lock)
STUB(prrelvm)
STUB(sendto)
STUB(sir_on)
STUB(subyte)
STUB(idmap_get_door)
STUB(vpanic)
STUB(pagezero)
STUB(i_ddi_remove_softint)
STUB(dcopy_free)
STUB(copyinstr)
STUB(thread_load)
STUB(makectty)
STUB(set_all_zone_usr_proc_sys)
STUB(hat_flush_range)
STUB(impl_assign_instance)
STUB(randtick)
STUB(copyoutstr_noerr)
STUB(hat_memload_region)
STUB(map_addr)
STUB(map_pgsz)
STUB(devi_stillreferenced)
STUB(i_ddi_cacheattr_to_hatacc)
STUB(spec_unfence_snode)
STUB(i_ddi_devacc_to_hatacc)
STUB(prbarrier)
STUB(audit_setfsat_path)
STUB(hat_dump)
STUB(hat_exit)
STUB(hat_sync)
STUB(gethrestime)
STUB(suword8_noerr)
STUB(recvmsg)
STUB(suword16_noerr)
STUB(fuword16_noerr)
STUB(au_free_rec)
STUB(cpu_intr_swtch_exit)
STUB(clconf_maximum_nodeid)
STUB(devfs_clean)
STUB(sysdc_thread_enter)
STUB(dump_plat_pfn)
STUB(hat_chgprot)
STUB(hat_chgattr)
STUB(syscall_ap)
STUB(tnf_opaque_array_1)
STUB(map_pgszcvec)
STUB(lwp_setrval)
STUB(semexit)
STUB(sendmsg)
STUB(setregs)
STUB(resume_from_zombie)
STUB(shmexit)
STUB(shmfork)
STUB(i_ddi_mem_alloc)
STUB(hat_supported)
STUB(spec_assoc_vp_with_devi)
STUB(dcopy_cmd_post)
STUB(dcopy_cmd_poll)
STUB(dcopy_cmd_free)
STUB(i_ddi_intr_redist_all_cpus)
STUB(impl_fix_props)
STUB(dld_autopush)
STUB(cladmin)
STUB(resume_from_intr)
STUB(pr_isobject)
STUB(spec_devi_open_count)
STUB(lwp_rtt_initial)
STUB(hat_clrattr)
STUB(hat_alloc)
STUB(hat_enter)
STUB(set_errno)
STUB(setsockopt)
STUB(getsockopt)
STUB(connect)
STUB(hat_probe)
STUB(copyout)
STUB(copystr)
STUB(ucopystr)
STUB(hat_share)
STUB(hat_setup)
STUB(splhigh)
STUB(hat_page_getshare)
STUB(hat_unlock_region)
STUB(hat_swapout)
STUB(sulword)
STUB(fastboot_update_and_load)
STUB(suword8)
STUB(ddi_get8)
STUB(ddi_put8)
STUB(gethrtime)
STUB(fifo_getinfo)
STUB(auditdoor)
STUB(ddi_rep_put8)
STUB(ddi_rep_get8)
STUB(hat_page_checkshare)
STUB(impl_ddi_prop_int_from_prom)
STUB(tod_get)
STUB(tod_set)
STUB(au_doormsg)
STUB(nl7c_sendfilev)
STUB(scalehrtime)
STUB(so_socketpair)
STUB(getpeername)
STUB(hat_page_getattr)
STUB(recvfrom)
STUB(i_ddi_check_cache_attr)
STUB(hat_memload_array)
STUB(getuserpc)
STUB(prexecstart)
STUB(hat_unload_callback)
STUB(door_ki_upcall_limited)
STUB(hat_kpm_page2va)
STUB(gethrtime_waitfree)
STUB(hat_unshare)
STUB(i_ddi_set_softint_pri)
STUB(makespecvp)
STUB(common_specvp)
STUB(suword32_noerr)
STUB(fuword32_noerr)
STUB(plat_tod_fault)
STUB(suword32)
STUB(suword16)
STUB(fuword16)
STUB(fuword32)
STUB(hat_join_region)
STUB(kidmap_getsidbygid)
STUB(prexecend)
STUB(kidmap_getgidbysid)
STUB(kidmap_getuidbysid)
STUB(kidmap_getsidbyuid)
STUB(impl_acc_hdl_get)
STUB(i_ddi_trigger_softint)
STUB(exec_get_spslew)
STUB(debug_enter)
STUB(pr_allstopped)
STUB(zfs_prop_to_name)
STUB(dtrace_membar_producer)
STUB(idmap_purge_cache)
STUB(dtrace_gethrtime)
STUB(sosendfile64)
STUB(prefetch_smap_w)
STUB(hat_getpagesize)
STUB(cpu_intr_swtch_enter)
STUB(devfs_walk)
STUB(hat_getattr)
STUB(prefetch_page_r)
STUB(fulword)
STUB(fuword8)
STUB(fss_freebuf)
STUB(hat_memload_array_region)
STUB(hat_kpm_mapin)
STUB(spec_getvnodeops)
STUB(hat_thread_exit)
STUB(hat_dup_region)
STUB(fss_changepset)
STUB(fss_changeproj)
STUB(lwp_stk_init)
STUB(lwp_stk_fini)
STUB(hat_free_end)
STUB(lwp_pcb_exit)
STUB(lwp_load)
STUB(hat_dup)
STUB(hat_map)
STUB(hat_kpm_mapout)
STUB(set_proc_post_sys)
STUB(e_ddi_copytodev)
STUB(idmap_unreg_dh)
STUB(set_idle_cpu)
STUB(gethrestime_lasttick)
STUB(lock_set_spl)
STUB(highbit)
STUB(cl_flk_state_transition_notify)
STUB(drv_usecwait)
STUB(set_base_spl)
STUB(ftrace_interrupt_disable)
STUB(impl_free_instance)
STUB(intr_passivate)
STUB(dcopy_alloc)
STUB(valid_va_range)
STUB(ddi_get64)
STUB(ddi_get32)
STUB(ddi_get16)
STUB(ddi_put64)
STUB(ddi_put32)
STUB(ddi_put16)
STUB(sock_getfasync)
STUB(dtrace_interrupt_disable)
STUB(lwp_freeregs)
STUB(xcopyin_nta)
STUB(i_ddi_mem_free)
STUB(hat_page_setattr)
STUB(impl_setup_ddi)
STUB(shutdown)
STUB(audit_anchorpath)
STUB(i_convert_boot_device_name)
STUB(dsl_prop_get)
STUB(__aeabi_llsr)
STUB(__aeabi_llsl)
STUB(siron)
STUB(panic_saveregs)
STUB(panic_savetrap)
STUB(panic_quiesce_hw)
STUB(panic_stopcpus)
STUB(mp_cpu_poweroff)
STUB(cpu_create_intrstat)
STUB(mp_cpu_faulted_enter)
STUB(pg_plat_hw_shared)
STUB(cpupm_plat_domain_id)
STUB(bp_color)
STUB(pg_plat_cmt_policy)
STUB(siron_poke_cpu)
STUB(getpil)
STUB(panic_showtrap)
STUB(cpu_disable_intr)
STUB(setjmp)
STUB(traceregs)
STUB(unscalehrtime)
STUB(cpupm_plat_state_enumerate)
STUB(mp_cpu_stop)
STUB(pg_plat_cpus_share)
STUB(pg_plat_hw_rank)
STUB(cpu_enable_intr)
STUB(mp_cpu_faulted_exit)
STUB(mp_cpu_unconfigure)
STUB(pg_plat_get_core_id)
STUB(get_cpu_mstate)
STUB(elfexec)
STUB(pg_plat_hw_instance_id)
STUB(mapexec_brand)
STUB(panic_trigger)
STUB(cpu_delete_intrstat)
STUB(panic_dump_hw)
STUB(panic_enter_hw)
STUB(cpupm_plat_change_state)
STUB(mp_cpu_start)
STUB(mp_cpu_configure)
STUB(mach_cpu_pause)
STUB(kdi_siron)
STUB(ld_ib_prop)
STUB(mp_cpu_poweron)
STUB(strplumb)
STUB(consconfig)
STUB(release_bootstrap)
STUB(cluster)
STUB(reset_syscall_args)
STUB(halt)
STUB(cbe_init_pre)
STUB(cbe_init)
STUB(post_startup)
STUB(start_other_cpus)
STUB(dtrace_safe_synchronous_signal)
STUB(prstop)
STUB(prnotify)
STUB(prnostep)
STUB(sendsig)
STUB(audit_core_start)
STUB(dtrace_safe_defer_signal)
STUB(audit_core_finish)
STUB(reset)
STUB(prom_enter_mon)
STUB(mutex_gettick)
STUB(splr)
STUB(ulock_clear)
STUB(cu_plat_cpc_init)
STUB(kcpc_hw_load_pcbe)
STUB(spl_xcall)
STUB(devfs_reset_perm)
STUB(clboot_modload)
STUB(devfs_remdrv_cleanup)
STUB(sdev_modctl_readdir_free)
STUB(prom_panic)
STUB(hat_kpm_mseghash_clear)
STUB(add_physmem_cb)
STUB(sdev_modctl_readdir)
STUB(ulock_try)
STUB(ppmapout)
STUB(ppmapin)
STUB(ppcopy)
STUB(cpu_call)
STUB(hat_reserve)
STUB(sdev_modctl_devexists)
STUB(devname_profile_update)
STUB(spa_boot_init)
STUB(clboot_rootconf)
STUB(sync_data_memory)
STUB(pagescrub)
STUB(clboot_mountroot)
STUB(devname_filename_register)
STUB(hat_kpm_mseghash_update)
STUB(hat_page_demote)
STUB(strplumb_get_netdev_path)
STUB(arm_gettick)