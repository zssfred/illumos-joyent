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
 * Fake stubs that we need to advance
 */
extern void bop_panic(const char *);

void
kas(void)
{
	bop_panic("kas");
}

void
bcmp(void)
{
	bop_panic("bcmp");
}

void
kdi_flush_caches(void)
{
	bop_panic("kdi_flush_caches");
}

void
kvseg(void)
{
	bop_panic("kvseg");
}

void
kobj_text_alloc(void)
{
	bop_panic("kobj_text_alloc");
}

void
mod_release_mod(void)
{
	bop_panic("mod_release_mod");
}

void
last_module_id(void)
{
	bop_panic("last_module_id");
}

void
heaptext_arena(void)
{
	bop_panic("heaptext_arena");
}

void
kdi_range_is_nontoxic(void)
{
	bop_panic("kdi_range_is_nontoxic");
}

void
dcache_flushall(void)
{
	bop_panic("dcache_flushall");
}

void
SHA1Final(void)
{
	bop_panic("SHA1Final");
}

void
mod_lock(void)
{
	bop_panic("mod_lock");
}

void
moddebug(void)
{
	bop_panic("moddebug");
}

void
heap_arena(void)
{
	bop_panic("heap_arena");
}

void
kdi_pwrite(void)
{
	bop_panic("kdi_pwrite");
}

int boothowto;

void
e_data(void)
{
	bop_panic("e_data");
}

void
e_text(void)
{
	bop_panic("e_text");
}

void
SHA1Update(void)
{
	bop_panic("SHA1Update");
}

void
hat_unload(void)
{
	bop_panic("hat_unload");
}

void
s_data(void)
{
	bop_panic("s_data");
}

void
s_text(void)
{
	bop_panic("s_text");
}

void
rootdir(void)
{
	bop_panic("rootdir");
}

void
stubs_base(void)
{
	bop_panic("stubs_base");
}

void
rw_exit(void)
{
	bop_panic("rw_exit");
}

void
hat_getpfnum(void)
{
	bop_panic("hat_getpfnum");
}

void
mod_load_requisite(void)
{
	bop_panic("mod_load_requisite");
}

void
hat_devload(void)
{
	bop_panic("hat_devload");
}

void
kdi_vtop(void)
{
	bop_panic("kdi_vtop");
}

void
stubs_end(void)
{
	bop_panic("stubs_end");
}

void
SHA1Init(void)
{
	bop_panic("SHA1Init");
}

void
membar_producer(void)
{
	bop_panic("membar_producer");
}

void
mutex_exit(void)
{
	bop_panic("mutex_exit");
}

void
mutex_init(void)
{
	bop_panic("mutex_init");
}

void
rw_enter(void)
{
	bop_panic("rw_enter");
}

void
segkmem_free(void)
{
	bop_panic("segkmem_free");
}

void
mutex_destroy(void)
{
	bop_panic("mutex_destroy");
}

void
mutex_enter(void)
{
	bop_panic("mutex_enter");
}

void
kobj_texthole_free(void)
{
	bop_panic("kobj_texthole_free");
}

void
kdi_pread(void)
{
	bop_panic("kdi_pread");
}

void
modrootloaded(void)
{
	bop_panic("modrootloaded");
}

void
kobj_vmem_init(void)
{
	bop_panic("kobj_vmem_init");
}

void
mutex_owned(void)
{
	bop_panic("mutex_owned");
}

void
anon_init(void)
{
	bop_panic("anon_init");
}

void
physmem(void)
{
	bop_panic("physmem");
}

void
cu_init(void)
{
	bop_panic("cu_init");
}

void
vfsinit(void)
{
	bop_panic("vfsinit");
}

void
cpr(void)
{
	bop_panic("cpr");
}

void
acct(void)
{
	bop_panic("acct");
}

void
bind(void)
{
	bop_panic("bind");
}

void
recv(void)
{
	bop_panic("recv");
}

void
send(void)
{
	bop_panic("send");
}

void
spl0(void)
{
	bop_panic("spl0");
}

void
spl7(void)
{
	bop_panic("spl7");
}

void
spl8(void)
{
	bop_panic("spl8");
}

void
splx(void)
{
	bop_panic("splx");
}

void
atomic_inc_ulong_nv(void)
{
	bop_panic("atomic_inc_ulong_nv");
}

void
page_get_user_pagesize(void)
{
	bop_panic("page_get_user_pagesize");
}

void
audit_init_module(void)
{
	bop_panic("audit_init_module");
}

void
page_pptonum(void)
{
	bop_panic("page_pptonum");
}

void
i_ddi_intr_ops(void)
{
	bop_panic("i_ddi_intr_ops");
}

void
dcopy_cmd_alloc(void)
{
	bop_panic("dcopy_cmd_alloc");
}

void
impl_acc_hdl_free(void)
{
	bop_panic("impl_acc_hdl_free");
}

void
plat_hold_page(void)
{
	bop_panic("plat_hold_page");
}

void
check_status(void)
{
	bop_panic("check_status");
}

void
audit_symlink_create(void)
{
	bop_panic("audit_symlink_create");
}

void
page_pp_lock(void)
{
	bop_panic("page_pp_lock");
}

void
lwpchan_delete_mapping(void)
{
	bop_panic("lwpchan_delete_mapping");
}

void
lwp_mutex_register(void)
{
	bop_panic("lwp_mutex_register");
}

void
hat_page_clrattr(void)
{
	bop_panic("hat_page_clrattr");
}

void
copyinstr_noerr(void)
{
	bop_panic("copyinstr_noerr");
}

void
modunload_disable(void)
{
	bop_panic("modunload_disable");
}

void
audit(void)
{
	bop_panic("audit");
}

void
cas32(void)
{
	bop_panic("cas32");
}

void
cas64(void)
{
	bop_panic("cas64");
}

void
copyoutstr(void)
{
	bop_panic("copyoutstr");
}

void
getfp(void)
{
	bop_panic("getfp");
}

void
htonl(void)
{
	bop_panic("htonl");
}

void
indir(void)
{
	bop_panic("indir");
}

void
idmap_reg_dh(void)
{
	bop_panic("idmap_reg_dh");
}

void
kcopy(void)
{
	bop_panic("kcopy");
}

void
kzero(void)
{
	bop_panic("kzero");
}

void
nosys(void)
{
	bop_panic("nosys");
}

void
ntohl(void)
{
	bop_panic("ntohl");
}

void
ntohs(void)
{
	bop_panic("ntohs");
}

void
fifo_vfastoff(void)
{
	bop_panic("fifo_vfastoff");
}

void
splhi(void)
{
	bop_panic("splhi");
}

void
ucopy(void)
{
	bop_panic("ucopy");
}

void
uzero(void)
{
	bop_panic("uzero");
}

void
lwp_sema_post(void)
{
	bop_panic("lwp_sema_post");
}

void
page_subclaim_pages(void)
{
	bop_panic("page_subclaim_pages");
}

void
lwp_mutex_wakeup(void)
{
	bop_panic("lwp_mutex_wakeup");
}

void
i_ddi_acc_clr_fault(void)
{
	bop_panic("i_ddi_acc_clr_fault");
}

void
audit_setf(void)
{
	bop_panic("audit_setf");
}

void
audit_priv(void)
{
	bop_panic("audit_priv");
}

void
audit_exec(void)
{
	bop_panic("audit_exec");
}

void
audit_exit(void)
{
	bop_panic("audit_exit");
}

void
hat_leave_region(void)
{
	bop_panic("hat_leave_region");
}

void
door_ki_upcall(void)
{
	bop_panic("door_ki_upcall");
}

void
unset_idle_cpu(void)
{
	bop_panic("unset_idle_cpu");
}

void
thread_onproc(void)
{
	bop_panic("thread_onproc");
}

void
impl_make_parlist(void)
{
	bop_panic("impl_make_parlist");
}

void
lwp_cond_signal(void)
{
	bop_panic("lwp_cond_signal");
}

void
set_proc_ast(void)
{
	bop_panic("set_proc_ast");
}

void
ddi_rep_put64(void)
{
	bop_panic("ddi_rep_put64");
}

void
ddi_rep_put32(void)
{
	bop_panic("ddi_rep_put32");
}

void
ddi_rep_put16(void)
{
	bop_panic("ddi_rep_put16");
}

void
group_page_unlock(void)
{
	bop_panic("group_page_unlock");
}

void
boot_virt_alloc(void)
{
	bop_panic("boot_virt_alloc");
}

void
ddi_rep_get64(void)
{
	bop_panic("ddi_rep_get64");
}

void
ddi_rep_get32(void)
{
	bop_panic("ddi_rep_get32");
}

void
ddi_rep_get16(void)
{
	bop_panic("ddi_rep_get16");
}

void
i_ddi_map_fault(void)
{
	bop_panic("i_ddi_map_fault");
}

void
lwp_stk_cache_init(void)
{
	bop_panic("lwp_stk_cache_init");
}

void
vfs_list_read_lock(void)
{
	bop_panic("vfs_list_read_lock");
}

void
dtrace_interrupt_enable(void)
{
	bop_panic("dtrace_interrupt_enable");
}

void
ftrace_interrupt_enable(void)
{
	bop_panic("ftrace_interrupt_enable");
}

void
kcpc_passivate(void)
{
	bop_panic("kcpc_passivate");
}

void
lwp_mutex_unlock(void)
{
	bop_panic("lwp_mutex_unlock");
}

void
anon_private(void)
{
	bop_panic("anon_private");
}

void
anon_swap_adjust(void)
{
	bop_panic("anon_swap_adjust");
}

void
xcopyout_nta(void)
{
	bop_panic("xcopyout_nta");
}

void
segkmem_alloc_lp(void)
{
	bop_panic("segkmem_alloc_lp");
}

void
hat_pagesync(void)
{
	bop_panic("hat_pagesync");
}

void
console_enter(void)
{
	bop_panic("console_enter");
}

void
spec_snode_walk(void)
{
	bop_panic("spec_snode_walk");
}

void
read_binding_file(void)
{
	bop_panic("read_binding_file");
}

void
audit_chdirec(void)
{
	bop_panic("audit_chdirec");
}

void
prinvalidate(void)
{
	bop_panic("prinvalidate");
}

void
mod_name_to_major(void)
{
	bop_panic("mod_name_to_major");
}

void
mod_name_to_modid(void)
{
	bop_panic("mod_name_to_modid");
}

void
vfs_mntpoint2vfsp(void)
{
	bop_panic("vfs_mntpoint2vfsp");
}

void
lock_clear(void)
{
	bop_panic("lock_clear");
}

void
membar_enter(void)
{
	bop_panic("membar_enter");
}

void
ka_init(void)
{
	bop_panic("ka_init");
}

void
page_pp_unlock(void)
{
	bop_panic("page_pp_unlock");
}

void
page_io_unlock(void)
{
	bop_panic("page_io_unlock");
}

void
vfs_getvfsswbyvfsops(void)
{
	bop_panic("vfs_getvfsswbyvfsops");
}

void
loadable_syscall(void)
{
	bop_panic("loadable_syscall");
}

void
unlock_hw_class_list(void)
{
	bop_panic("unlock_hw_class_list");
}

void
sockconfig(void)
{
	bop_panic("sockconfig");
}

void
fuword8_noerr(void)
{
	bop_panic("fuword8_noerr");
}

void
lwp_detach_brand_hdlrs(void)
{
	bop_panic("lwp_detach_brand_hdlrs");
}

void
mod_hash_null_keydtor(void)
{
	bop_panic("mod_hash_null_keydtor");
}

void
valid_va_range_aligned(void)
{
	bop_panic("valid_va_range_aligned");
}

void
lwp_forkregs(void)
{
	bop_panic("lwp_forkregs");
}

void
devfs_devpolicy(void)
{
	bop_panic("devfs_devpolicy");
}

void
hat_stats_disable(void)
{
	bop_panic("hat_stats_disable");
}

void
vfs_freevfsops_by_type(void)
{
	bop_panic("vfs_freevfsops_by_type");
}

void
page_tryupgrade(void)
{
	bop_panic("page_tryupgrade");
}

void
mod_hash_create_ptrhash(void)
{
	bop_panic("mod_hash_create_ptrhash");
}

void
page_num_user_pagesizes(void)
{
	bop_panic("page_num_user_pagesizes");
}

void
pr_free_watched_pages(void)
{
	bop_panic("pr_free_watched_pages");
}

void
install_utrap(void)
{
	bop_panic("install_utrap");
}

void
fsop_mountroot(void)
{
	bop_panic("fsop_mountroot");
}

void
page_vnode_mutex(void)
{
	bop_panic("page_vnode_mutex");
}

void
dtrace_membar_consumer(void)
{
	bop_panic("dtrace_membar_consumer");
}

void
socket_sendmblk(void)
{
	bop_panic("socket_sendmblk");
}

void
audit_symlink(void)
{
	bop_panic("audit_symlink");
}

void
i_ddi_apply_range(void)
{
	bop_panic("i_ddi_apply_range");
}

void
lock_clear_splx(void)
{
	bop_panic("lock_clear_splx");
}

void
page_get_pagesize(void)
{
	bop_panic("page_get_pagesize");
}

void
audit_strputmsg(void)
{
	bop_panic("audit_strputmsg");
}

void
thread_transition(void)
{
	bop_panic("thread_transition");
}

void
i_ddi_alloc_intr_phdl(void)
{
	bop_panic("i_ddi_alloc_intr_phdl");
}

void
i_ddi_acc_set_fault(void)
{
	bop_panic("i_ddi_acc_set_fault");
}

void
mod_rele_dev_by_major(void)
{
	bop_panic("mod_rele_dev_by_major");
}

void
mod_hold_dev_by_major(void)
{
	bop_panic("mod_hold_dev_by_major");
}

void
clconf_get_nodeid(void)
{
	bop_panic("clconf_get_nodeid");
}

void
atomic_and_long(void)
{
	bop_panic("atomic_and_long");
}

void
e_ddi_copyfromdev(void)
{
	bop_panic("e_ddi_copyfromdev");
}

void
atomic_inc_uint(void)
{
	bop_panic("atomic_inc_uint");
}

void
impl_acc_hdl_alloc(void)
{
	bop_panic("impl_acc_hdl_alloc");
}

void
mod_hash_destroy_ptrhash(void)
{
	bop_panic("mod_hash_destroy_ptrhash");
}

void
sdev_devstate_change(void)
{
	bop_panic("sdev_devstate_change");
}

void
translate_devid(void)
{
	bop_panic("translate_devid");
}

void
lwpchan_destroy_cache(void)
{
	bop_panic("lwpchan_destroy_cache");
}

void
impl_keep_instance(void)
{
	bop_panic("impl_keep_instance");
}

void
impl_free_parlist(void)
{
	bop_panic("impl_free_parlist");
}

void
hat_stats_enable(void)
{
	bop_panic("hat_stats_enable");
}

void
hr_clock_unlock(void)
{
	bop_panic("hr_clock_unlock");
}

void
audit_closef(void)
{
	bop_panic("audit_closef");
}

void
hat_join_srd(void)
{
	bop_panic("hat_join_srd");
}

void
hat_softlock(void)
{
	bop_panic("hat_softlock");
}

void
spec_is_clone(void)
{
	bop_panic("spec_is_clone");
}

void
audit_fdsend(void)
{
	bop_panic("audit_fdsend");
}

void
audit_fdrecv(void)
{
	bop_panic("audit_fdrecv");
}

void
random_get_bytes(void)
{
	bop_panic("random_get_bytes");
}

void
audit_finish(void)
{
	bop_panic("audit_finish");
}

void
page_destroy_free(void)
{
	bop_panic("page_destroy_free");
}

void
fs_build_vector(void)
{
	bop_panic("fs_build_vector");
}

void
pf_is_memory(void)
{
	bop_panic("pf_is_memory");
}

void
peekpoke_mem(void)
{
	bop_panic("peekpoke_mem");
}

void
ddi_fm_capable(void)
{
	bop_panic("ddi_fm_capable");
}

void
page_try_demote_pages(void)
{
	bop_panic("page_try_demote_pages");
}

void
fastboot_update_config(void)
{
	bop_panic("fastboot_update_config");
}

void
audit_savepath(void)
{
	bop_panic("audit_savepath");
}

void
hat_get_mapped_size(void)
{
	bop_panic("hat_get_mapped_size");
}

void
impl_parlist_to_major(void)
{
	bop_panic("impl_parlist_to_major");
}

void
thread_lock_high(void)
{
	bop_panic("thread_lock_high");
}

void
lock_hw_class_list(void)
{
	bop_panic("lock_hw_class_list");
}

void
segkmem_free_lp(void)
{
	bop_panic("segkmem_free_lp");
}

void
mod_hash_insert_reserve(void)
{
	bop_panic("mod_hash_insert_reserve");
}

void
thread_stk_init(void)
{
	bop_panic("thread_stk_init");
}

void
hat_free_start(void)
{
	bop_panic("hat_free_start");
}

void
impl_ddi_sunbus_initchild(void)
{
	bop_panic("impl_ddi_sunbus_initchild");
}

void
lwp_rtt(void)
{
	bop_panic("lwp_rtt");
}

void
prlwpfree(void)
{
	bop_panic("prlwpfree");
}

void
prlwpexit(void)
{
	bop_panic("prlwpexit");
}

void
page_lookup_create(void)
{
	bop_panic("page_lookup_create");
}

void
hat_memload(void)
{
	bop_panic("hat_memload");
}

void
page_io_locked(void)
{
	bop_panic("page_io_locked");
}

void
console_exit(void)
{
	bop_panic("console_exit");
}

void
page_lookup_nowait(void)
{
	bop_panic("page_lookup_nowait");
}

void
map_addr_vacalign_check(void)
{
	bop_panic("map_addr_vacalign_check");
}

void
hat_pageunload(void)
{
	bop_panic("hat_pageunload");
}

void
spec_fence_snode(void)
{
	bop_panic("spec_fence_snode");
}

void
page_alloc_pages(void)
{
	bop_panic("page_alloc_pages");
}

void
copyout_noerr(void)
{
	bop_panic("copyout_noerr");
}

void
audit_vncreate_finish(void)
{
	bop_panic("audit_vncreate_finish");
}

void
anon_alloc(void)
{
	bop_panic("anon_alloc");
}

void
modload(void)
{
	bop_panic("modload");
}

void
modreap(void)
{
	bop_panic("modreap");
}

void
on_fault(void)
{
	bop_panic("on_fault");
}

void
door_ki_lookup(void)
{
	bop_panic("door_ki_lookup");
}

void
anon_pages(void)
{
	bop_panic("anon_pages");
}

void
lbolt_softint_post(void)
{
	bop_panic("lbolt_softint_post");
}

void
page_migrate(void)
{
	bop_panic("page_migrate");
}

void
door_revoke_all(void)
{
	bop_panic("door_revoke_all");
}

void
ndi_fmc_entry_error(void)
{
	bop_panic("ndi_fmc_entry_error");
}

void
anon_array_try_enter(void)
{
	bop_panic("anon_array_try_enter");
}

void
spec_is_selfclone(void)
{
	bop_panic("spec_is_selfclone");
}

void
page_destroy_pages(void)
{
	bop_panic("page_destroy_pages");
}

void
anon_get_slot(void)
{
	bop_panic("anon_get_slot");
}

void
set_anoninfo(void)
{
	bop_panic("set_anoninfo");
}

void
prefetch_write_many(void)
{
	bop_panic("prefetch_write_many");
}

void
dump_plat_addr(void)
{
	bop_panic("dump_plat_addr");
}

void
dump_plat_data(void)
{
	bop_panic("dump_plat_data");
}

void
au_to_arg32(void)
{
	bop_panic("au_to_arg32");
}

void
mod_hash_iddata_gen(void)
{
	bop_panic("mod_hash_iddata_gen");
}

void
anon_shmap_free_pages(void)
{
	bop_panic("anon_shmap_free_pages");
}

void
random_get_pseudo_bytes(void)
{
	bop_panic("random_get_pseudo_bytes");
}

void
num_phys_pages(void)
{
	bop_panic("num_phys_pages");
}

void
page_relocate_cage(void)
{
	bop_panic("page_relocate_cage");
}

void
mutex_tryenter(void)
{
	bop_panic("mutex_tryenter");
}

void
cmp_set_nosteal_interval(void)
{
	bop_panic("cmp_set_nosteal_interval");
}

void
no_fault(void)
{
	bop_panic("no_fault");
}

void
anon_dup(void)
{
	bop_panic("anon_dup");
}

void
sync_icache(void)
{
	bop_panic("sync_icache");
}

void
vfs_rlock_wait(void)
{
	bop_panic("vfs_rlock_wait");
}

void
lock_try(void)
{
	bop_panic("lock_try");
}

void
lock_set(void)
{
	bop_panic("lock_set");
}

void
sock_getmsg(void)
{
	bop_panic("sock_getmsg");
}

void
getsetcontext(void)
{
	bop_panic("getsetcontext");
}

void
page_mark_migrate(void)
{
	bop_panic("page_mark_migrate");
}

void
i_ddi_rnumber_to_regspec(void)
{
	bop_panic("i_ddi_rnumber_to_regspec");
}

void
page_exists(void)
{
	bop_panic("page_exists");
}

void
lock_spin_try(void)
{
	bop_panic("lock_spin_try");
}

void
anon_create(void)
{
	bop_panic("anon_create");
}

void
anon_decref(void)
{
	bop_panic("anon_decref");
}

void
anon_fill_cow_holes(void)
{
	bop_panic("anon_fill_cow_holes");
}

void
vfs_getops(void)
{
	bop_panic("vfs_getops");
}

void
vfs_getresource(void)
{
	bop_panic("vfs_getresource");
}

void
mod_getctl(void)
{
	bop_panic("mod_getctl");
}

void
hwc_free_spec_list(void)
{
	bop_panic("hwc_free_spec_list");
}

void
vfs_has_feature(void)
{
	bop_panic("vfs_has_feature");
}

void
lwp_cond_broadcast(void)
{
	bop_panic("lwp_cond_broadcast");
}

void
_insque(void)
{
	bop_panic("_insque");
}

void
sock_putmsg(void)
{
	bop_panic("sock_putmsg");
}

void
pr_isself(void)
{
	bop_panic("pr_isself");
}

void
save_syscall_args(void)
{
	bop_panic("save_syscall_args");
}

void
getsockname(void)
{
	bop_panic("getsockname");
}

void
fss_allocbuf(void)
{
	bop_panic("fss_allocbuf");
}

void
poke_cpu(void)
{
	bop_panic("poke_cpu");
}

void
page_io_trylock(void)
{
	bop_panic("page_io_trylock");
}

void
anon_grow(void)
{
	bop_panic("anon_grow");
}

void
non_anon(void)
{
	bop_panic("non_anon");
}

void
anon_free(void)
{
	bop_panic("anon_free");
}

void
lbolt_softint_add(void)
{
	bop_panic("lbolt_softint_add");
}

void
on_trap(void)
{
	bop_panic("on_trap");
}

void
anon_zero(void)
{
	bop_panic("anon_zero");
}

void
vfs_unrefvfssw(void)
{
	bop_panic("vfs_unrefvfssw");
}

void
anon_dup_fill_holes(void)
{
	bop_panic("anon_dup_fill_holes");
}

void
page_lookup(void)
{
	bop_panic("page_lookup");
}

void
ip_ocsum(void)
{
	bop_panic("ip_ocsum");
}

void
fsop_vget(void)
{
	bop_panic("fsop_vget");
}

void
fsop_root(void)
{
	bop_panic("fsop_root");
}

void
audit_vncreate_start(void)
{
	bop_panic("audit_vncreate_start");
}

void
i_ddi_free_intr_phdl(void)
{
	bop_panic("i_ddi_free_intr_phdl");
}

void
accept(void)
{
	bop_panic("accept");
}

void
atomic_set_long_excl(void)
{
	bop_panic("atomic_set_long_excl");
}

void
kcopy_nta(void)
{
	bop_panic("kcopy_nta");
}

void
audit_devpolicy(void)
{
	bop_panic("audit_devpolicy");
}

void
page_mem_avail(void)
{
	bop_panic("page_mem_avail");
}

void
door_exit(void)
{
	bop_panic("door_exit");
}

void
door_fork(void)
{
	bop_panic("door_fork");
}

void
door_slam(void)
{
	bop_panic("door_slam");
}

void
_remque(void)
{
	bop_panic("_remque");
}

void
valid_usr_range(void)
{
	bop_panic("valid_usr_range");
}

void
i_ddi_bus_map(void)
{
	bop_panic("i_ddi_bus_map");
}

void
caller(void)
{
	bop_panic("caller");
}

void
casptr(void)
{
	bop_panic("casptr");
}

void
snf_segmap(void)
{
	bop_panic("snf_segmap");
}

void
so_socket(void)
{
	bop_panic("so_socket");
}

void
copyin(void)
{
	bop_panic("copyin");
}

void
socket_setsockopt(void)
{
	bop_panic("socket_setsockopt");
}

void
getpcstack(void)
{
	bop_panic("getpcstack");
}

void
va_to_pfn(void)
{
	bop_panic("va_to_pfn");
}

void
mod_sysctl(void)
{
	bop_panic("mod_sysctl");
}

void
mod_sysvar(void)
{
	bop_panic("mod_sysvar");
}

void
specfind(void)
{
	bop_panic("specfind");
}

void
i_ddi_drv_ereport_post(void)
{
	bop_panic("i_ddi_drv_ereport_post");
}

void
gethrestime_sec(void)
{
	bop_panic("gethrestime_sec");
}

void
hat_unlock(void)
{
	bop_panic("hat_unlock");
}

void
vfs_unlock(void)
{
	bop_panic("vfs_unlock");
}

void
fsop_statfs(void)
{
	bop_panic("fsop_statfs");
}

void
ovbcopy(void)
{
	bop_panic("ovbcopy");
}

void
au_uwrite(void)
{
	bop_panic("au_uwrite");
}

void
page_unlock(void)
{
	bop_panic("page_unlock");
}

void
page_unresv(void)
{
	bop_panic("page_unresv");
}

void
disp_lock_enter_high(void)
{
	bop_panic("disp_lock_enter_high");
}

void
spec_segmap(void)
{
	bop_panic("spec_segmap");
}

void
vfs_lock_wait(void)
{
	bop_panic("vfs_lock_wait");
}

void
exec_set_sp(void)
{
	bop_panic("exec_set_sp");
}

void
ddi_fm_ereport_post(void)
{
	bop_panic("ddi_fm_ereport_post");
}

void
copyin_noerr(void)
{
	bop_panic("copyin_noerr");
}

void
pty_initspace(void)
{
	bop_panic("pty_initspace");
}

void
audit_setppriv(void)
{
	bop_panic("audit_setppriv");
}

void
page_szc_lock(void)
{
	bop_panic("page_szc_lock");
}

void
listen(void)
{
	bop_panic("listen");
}

void
lowbit(void)
{
	bop_panic("lowbit");
}

void
mdboot(void)
{
	bop_panic("mdboot");
}

void
modctl(void)
{
	bop_panic("modctl");
}

void
door_ki_rele(void)
{
	bop_panic("door_ki_rele");
}

void
door_ki_hold(void)
{
	bop_panic("door_ki_hold");
}

void
door_ki_info(void)
{
	bop_panic("door_ki_info");
}

void
door_ki_open(void)
{
	bop_panic("door_ki_open");
}

void
i_ddi_add_softint(void)
{
	bop_panic("i_ddi_add_softint");
}

void
prexit(void)
{
	bop_panic("prexit");
}

void
prfree(void)
{
	bop_panic("prfree");
}

void
prstep(void)
{
	bop_panic("prstep");
}

void
lwp_cond_wait(void)
{
	bop_panic("lwp_cond_wait");
}

void
kpreempt(void)
{
	bop_panic("kpreempt");
}

void
mdpreboot(void)
{
	bop_panic("mdpreboot");
}

void
resume(void)
{
	bop_panic("resume");
}

void
hr_clock_lock(void)
{
	bop_panic("hr_clock_lock");
}

void
prrelvm(void)
{
	bop_panic("prrelvm");
}

void
sendto(void)
{
	bop_panic("sendto");
}

void
sir_on(void)
{
	bop_panic("sir_on");
}

void
subyte(void)
{
	bop_panic("subyte");
}

void
idmap_get_door(void)
{
	bop_panic("idmap_get_door");
}

void
vfs_devismounted(void)
{
	bop_panic("vfs_devismounted");
}

void
membar_consumer(void)
{
	bop_panic("membar_consumer");
}

void
vpanic(void)
{
	bop_panic("vpanic");
}

void
page_add(void)
{
	bop_panic("page_add");
}

void
page_sub(void)
{
	bop_panic("page_sub");
}

void
page_szc(void)
{
	bop_panic("page_szc");
}

void
pagezero(void)
{
	bop_panic("pagezero");
}

void
i_ddi_remove_softint(void)
{
	bop_panic("i_ddi_remove_softint");
}

void
dcopy_free(void)
{
	bop_panic("dcopy_free");
}

void
mod_read_system_file(void)
{
	bop_panic("mod_read_system_file");
}

void
thread_stop(void)
{
	bop_panic("thread_stop");
}

void
vfs_setmntopt(void)
{
	bop_panic("vfs_setmntopt");
}

void
copyinstr(void)
{
	bop_panic("copyinstr");
}

void
thread_lock(void)
{
	bop_panic("thread_lock");
}

void
thread_load(void)
{
	bop_panic("thread_load");
}

void
makectty(void)
{
	bop_panic("makectty");
}

void
set_all_zone_usr_proc_sys(void)
{
	bop_panic("set_all_zone_usr_proc_sys");
}

void
hat_flush_range(void)
{
	bop_panic("hat_flush_range");
}

void
impl_assign_instance(void)
{
	bop_panic("impl_assign_instance");
}

void
randtick(void)
{
	bop_panic("randtick");
}

void
copyoutstr_noerr(void)
{
	bop_panic("copyoutstr_noerr");
}

void
hat_memload_region(void)
{
	bop_panic("hat_memload_region");
}

void
map_addr(void)
{
	bop_panic("map_addr");
}

void
map_pgsz(void)
{
	bop_panic("map_pgsz");
}

void
kphysm_setup_func_register(void)
{
	bop_panic("kphysm_setup_func_register");
}

void
kcage_cageout_wakeup(void)
{
	bop_panic("kcage_cageout_wakeup");
}

void
devi_stillreferenced(void)
{
	bop_panic("devi_stillreferenced");
}

void
i_ddi_cacheattr_to_hatacc(void)
{
	bop_panic("i_ddi_cacheattr_to_hatacc");
}

void
spec_unfence_snode(void)
{
	bop_panic("spec_unfence_snode");
}

void
i_ddi_devacc_to_hatacc(void)
{
	bop_panic("i_ddi_devacc_to_hatacc");
}

void
prbarrier(void)
{
	bop_panic("prbarrier");
}

void
audit_setfsat_path(void)
{
	bop_panic("audit_setfsat_path");
}

void
hat_dump(void)
{
	bop_panic("hat_dump");
}

void
hat_exit(void)
{
	bop_panic("hat_exit");
}

void
hat_sync(void)
{
	bop_panic("hat_sync");
}

void
gethrestime(void)
{
	bop_panic("gethrestime");
}

void
suword8_noerr(void)
{
	bop_panic("suword8_noerr");
}

void
recvmsg(void)
{
	bop_panic("recvmsg");
}

void
suword16_noerr(void)
{
	bop_panic("suword16_noerr");
}

void
fuword16_noerr(void)
{
	bop_panic("fuword16_noerr");
}

void
anon_disclaim(void)
{
	bop_panic("anon_disclaim");
}

void
au_free_rec(void)
{
	bop_panic("au_free_rec");
}

void
cpu_intr_swtch_exit(void)
{
	bop_panic("cpu_intr_swtch_exit");
}

void
clconf_maximum_nodeid(void)
{
	bop_panic("clconf_maximum_nodeid");
}

void
ndi_fm_handler_dispatch(void)
{
	bop_panic("ndi_fm_handler_dispatch");
}

void
hwc_get_child_spec(void)
{
	bop_panic("hwc_get_child_spec");
}

void
page_create_putback(void)
{
	bop_panic("page_create_putback");
}

void
i_mod_hash_insert_nosync(void)
{
	bop_panic("i_mod_hash_insert_nosync");
}

void
mod_hash_destroy_hash(void)
{
	bop_panic("mod_hash_destroy_hash");
}

void
page_io_wait(void)
{
	bop_panic("page_io_wait");
}

void
page_io_lock(void)
{
	bop_panic("page_io_lock");
}

void
devfs_clean(void)
{
	bop_panic("devfs_clean");
}

void
sysdc_thread_enter(void)
{
	bop_panic("sysdc_thread_enter");
}

void
dump_plat_pfn(void)
{
	bop_panic("dump_plat_pfn");
}

void
anon_get_next_ptr(void)
{
	bop_panic("anon_get_next_ptr");
}

void
fs_error(void)
{
	bop_panic("fs_error");
}

void
ddi_fm_acc_err_get(void)
{
	bop_panic("ddi_fm_acc_err_get");
}

void
hat_chgprot(void)
{
	bop_panic("hat_chgprot");
}

void
hat_chgattr(void)
{
	bop_panic("hat_chgattr");
}

void
syscall_ap(void)
{
	bop_panic("syscall_ap");
}

void
page_exists_physcontig(void)
{
	bop_panic("page_exists_physcontig");
}

void
tnf_opaque_array_1(void)
{
	bop_panic("tnf_opaque_array_1");
}

void
map_pgszcvec(void)
{
	bop_panic("map_pgszcvec");
}

void
lwp_setrval(void)
{
	bop_panic("lwp_setrval");
}

void
semexit(void)
{
	bop_panic("semexit");
}

void
sendmsg(void)
{
	bop_panic("sendmsg");
}

void
page_szc_user_filtered(void)
{
	bop_panic("page_szc_user_filtered");
}

void
setregs(void)
{
	bop_panic("setregs");
}

void
resume_from_zombie(void)
{
	bop_panic("resume_from_zombie");
}

void
free_vp_pages(void)
{
	bop_panic("free_vp_pages");
}

void
page_hashout(void)
{
	bop_panic("page_hashout");
}

void
modunload_enable(void)
{
	bop_panic("modunload_enable");
}

void
shmexit(void)
{
	bop_panic("shmexit");
}

void
shmfork(void)
{
	bop_panic("shmfork");
}

void
i_ddi_mem_alloc(void)
{
	bop_panic("i_ddi_mem_alloc");
}

void
hat_supported(void)
{
	bop_panic("hat_supported");
}

void
mod_hash_clear(void)
{
	bop_panic("mod_hash_clear");
}

void
mod_hash_bystr(void)
{
	bop_panic("mod_hash_bystr");
}

void
spec_assoc_vp_with_devi(void)
{
	bop_panic("spec_assoc_vp_with_devi");
}

void
dcopy_cmd_post(void)
{
	bop_panic("dcopy_cmd_post");
}

void
dcopy_cmd_poll(void)
{
	bop_panic("dcopy_cmd_poll");
}

void
dcopy_cmd_free(void)
{
	bop_panic("dcopy_cmd_free");
}

void
i_ddi_intr_redist_all_cpus(void)
{
	bop_panic("i_ddi_intr_redist_all_cpus");
}

void
impl_fix_props(void)
{
	bop_panic("impl_fix_props");
}

void
dld_autopush(void)
{
	bop_panic("dld_autopush");
}

void
cladmin(void)
{
	bop_panic("cladmin");
}

void
resume_from_intr(void)
{
	bop_panic("resume_from_intr");
}

void
pr_isobject(void)
{
	bop_panic("pr_isobject");
}

void
spec_devi_open_count(void)
{
	bop_panic("spec_devi_open_count");
}

void
lwp_rtt_initial(void)
{
	bop_panic("lwp_rtt_initial");
}

void
hat_clrattr(void)
{
	bop_panic("hat_clrattr");
}

void
hat_alloc(void)
{
	bop_panic("hat_alloc");
}

void
get_class(void)
{
	bop_panic("get_class");
}

void
hat_enter(void)
{
	bop_panic("hat_enter");
}

void
set_errno(void)
{
	bop_panic("set_errno");
}

void
setsockopt(void)
{
	bop_panic("setsockopt");
}

void
getsockopt(void)
{
	bop_panic("getsockopt");
}

void
mod_major_to_name(void)
{
	bop_panic("mod_major_to_name");
}

void
connect(void)
{
	bop_panic("connect");
}

void
hat_probe(void)
{
	bop_panic("hat_probe");
}

void
copyout(void)
{
	bop_panic("copyout");
}

void
copystr(void)
{
	bop_panic("copystr");
}

void
ucopystr(void)
{
	bop_panic("ucopystr");
}

void
hat_share(void)
{
	bop_panic("hat_share");
}

void
hat_setup(void)
{
	bop_panic("hat_setup");
}

void
splhigh(void)
{
	bop_panic("splhigh");
}

void
lwp_mutex_timedlock(void)
{
	bop_panic("lwp_mutex_timedlock");
}

void
vfs_syncall(void)
{
	bop_panic("vfs_syncall");
}

void
mod_hash_create_idhash(void)
{
	bop_panic("mod_hash_create_idhash");
}

void
hat_page_getshare(void)
{
	bop_panic("hat_page_getshare");
}

void
disp_lock_exit(void)
{
	bop_panic("disp_lock_exit");
}

void
hat_unlock_region(void)
{
	bop_panic("hat_unlock_region");
}

void
hat_swapout(void)
{
	bop_panic("hat_swapout");
}

void
sulword(void)
{
	bop_panic("sulword");
}

void
systeminfo(void)
{
	bop_panic("systeminfo");
}

void
fastboot_update_and_load(void)
{
	bop_panic("fastboot_update_and_load");
}

void
suword8(void)
{
	bop_panic("suword8");
}

void
anon_map_getpages(void)
{
	bop_panic("anon_map_getpages");
}

void
ddi_get8(void)
{
	bop_panic("ddi_get8");
}

void
ddi_put8(void)
{
	bop_panic("ddi_put8");
}

void
anon_map_privatepages(void)
{
	bop_panic("anon_map_privatepages");
}

void
gethrtime(void)
{
	bop_panic("gethrtime");
}

void
fifo_getinfo(void)
{
	bop_panic("fifo_getinfo");
}

void
anon_array_enter(void)
{
	bop_panic("anon_array_enter");
}

void
auditdoor(void)
{
	bop_panic("auditdoor");
}

void
ddi_rep_put8(void)
{
	bop_panic("ddi_rep_put8");
}

void
ddi_rep_get8(void)
{
	bop_panic("ddi_rep_get8");
}

void
group_page_trylock(void)
{
	bop_panic("group_page_trylock");
}

void
hat_page_checkshare(void)
{
	bop_panic("hat_page_checkshare");
}

void
read_dacf_binding_file(void)
{
	bop_panic("read_dacf_binding_file");
}

void
vfs_unmountall(void)
{
	bop_panic("vfs_unmountall");
}

void
ddi_fm_acc_err_clear(void)
{
	bop_panic("ddi_fm_acc_err_clear");
}

void
disp_lock_enter(void)
{
	bop_panic("disp_lock_enter");
}

void
impl_ddi_prop_int_from_prom(void)
{
	bop_panic("impl_ddi_prop_int_from_prom");
}

void
anon_get_ptr(void)
{
	bop_panic("anon_get_ptr");
}

void
anon_getpage(void)
{
	bop_panic("anon_getpage");
}

void
vfs_dev2vfsp(void)
{
	bop_panic("vfs_dev2vfsp");
}

void
tod_get(void)
{
	bop_panic("tod_get");
}

void
tod_set(void)
{
	bop_panic("tod_set");
}

void
page_first(void)
{
	bop_panic("page_first");
}

void
vfs_setfsops(void)
{
	bop_panic("vfs_setfsops");
}

void
au_doormsg(void)
{
	bop_panic("au_doormsg");
}

void
page_nextn(void)
{
	bop_panic("page_nextn");
}

void
domount(void)
{
	bop_panic("domount");
}

void
make_mbind(void)
{
	bop_panic("make_mbind");
}

void
page_vpadd(void)
{
	bop_panic("page_vpadd");
}

void
page_vpsub(void)
{
	bop_panic("page_vpsub");
}

void
disp_lock_exit_nopreempt(void)
{
	bop_panic("disp_lock_exit_nopreempt");
}

void
vfs_getvfssw(void)
{
	bop_panic("vfs_getvfssw");
}

void
page_free_replacement_page(void)
{
	bop_panic("page_free_replacement_page");
}

void
nl7c_sendfilev(void)
{
	bop_panic("nl7c_sendfilev");
}

void
scalehrtime(void)
{
	bop_panic("scalehrtime");
}

void
fsop_vnstate(void)
{
	bop_panic("fsop_vnstate");
}

void
page_downgrade(void)
{
	bop_panic("page_downgrade");
}

void
so_socketpair(void)
{
	bop_panic("so_socketpair");
}

void
getpeername(void)
{
	bop_panic("getpeername");
}

void
hat_page_getattr(void)
{
	bop_panic("hat_page_getattr");
}

void
recvfrom(void)
{
	bop_panic("recvfrom");
}

void
i_ddi_check_cache_attr(void)
{
	bop_panic("i_ddi_check_cache_attr");
}

void
hat_memload_array(void)
{
	bop_panic("hat_memload_array");
}

void
atomic_swap_uint(void)
{
	bop_panic("atomic_swap_uint");
}

void
getuserpc(void)
{
	bop_panic("getuserpc");
}

void
atomic_add_64_nv(void)
{
	bop_panic("atomic_add_64_nv");
}

void
atomic_add_32_nv(void)
{
	bop_panic("atomic_add_32_nv");
}

void
prexecstart(void)
{
	bop_panic("prexecstart");
}

void
anon_map_createpages(void)
{
	bop_panic("anon_map_createpages");
}

void
anon_map_demotepages(void)
{
	bop_panic("anon_map_demotepages");
}

void
mod_hash_create_extended(void)
{
	bop_panic("mod_hash_create_extended");
}

void
i_mod_hash_clear_nosync(void)
{
	bop_panic("i_mod_hash_clear_nosync");
}

void
lwp_rwlock_sys(void)
{
	bop_panic("lwp_rwlock_sys");
}

void
hat_unload_callback(void)
{
	bop_panic("hat_unload_callback");
}

void
vfs_refvfssw(void)
{
	bop_panic("vfs_refvfssw");
}

void
door_ki_upcall_limited(void)
{
	bop_panic("door_ki_upcall_limited");
}

void
hat_kpm_page2va(void)
{
	bop_panic("hat_kpm_page2va");
}

void
gethrtime_waitfree(void)
{
	bop_panic("gethrtime_waitfree");
}

void
hat_unshare(void)
{
	bop_panic("hat_unshare");
}

void
page_create_va(void)
{
	bop_panic("page_create_va");
}

void
mod_hash_strkey_cmp(void)
{
	bop_panic("mod_hash_strkey_cmp");
}

void
dounmount(void)
{
	bop_panic("dounmount");
}

void
mod_hash_null_valdtor(void)
{
	bop_panic("mod_hash_null_valdtor");
}

void
page_numtopp_nolock(void)
{
	bop_panic("page_numtopp_nolock");
}

void
atomic_inc_ulong(void)
{
	bop_panic("atomic_inc_ulong");
}

void
i_ddi_set_softint_pri(void)
{
	bop_panic("i_ddi_set_softint_pri");
}

void
makespecvp(void)
{
	bop_panic("makespecvp");
}

void
page_promote_size(void)
{
	bop_panic("page_promote_size");
}

void
atomic_add_long(void)
{
	bop_panic("atomic_add_long");
}

void
common_specvp(void)
{
	bop_panic("common_specvp");
}

void
suword32_noerr(void)
{
	bop_panic("suword32_noerr");
}

void
fuword32_noerr(void)
{
	bop_panic("fuword32_noerr");
}

void
page_iolock_assert(void)
{
	bop_panic("page_iolock_assert");
}

void
page_addclaim(void)
{
	bop_panic("page_addclaim");
}

void
mod_hash_remove(void)
{
	bop_panic("mod_hash_remove");
}

void
plat_tod_fault(void)
{
	bop_panic("plat_tod_fault");
}

void
atomic_dec_32_nv(void)
{
	bop_panic("atomic_dec_32_nv");
}

void
mutex_sync(void)
{
	bop_panic("mutex_sync");
}

void
suword32(void)
{
	bop_panic("suword32");
}

void
suword16(void)
{
	bop_panic("suword16");
}

void
fuword16(void)
{
	bop_panic("fuword16");
}

void
fuword32(void)
{
	bop_panic("fuword32");
}

void
segkmem_alloc(void)
{
	bop_panic("segkmem_alloc");
}

void
hat_join_region(void)
{
	bop_panic("hat_join_region");
}

void
kidmap_getsidbygid(void)
{
	bop_panic("kidmap_getsidbygid");
}

void
prexecend(void)
{
	bop_panic("prexecend");
}

void
kidmap_getgidbysid(void)
{
	bop_panic("kidmap_getgidbysid");
}

void
kidmap_getuidbysid(void)
{
	bop_panic("kidmap_getuidbysid");
}

void
kidmap_getsidbyuid(void)
{
	bop_panic("kidmap_getsidbyuid");
}

void
vfs_getmntpoint(void)
{
	bop_panic("vfs_getmntpoint");
}

void
page_trylock(void)
{
	bop_panic("page_trylock");
}

void
mod_hash_create_strhash(void)
{
	bop_panic("mod_hash_create_strhash");
}

void
impl_acc_hdl_get(void)
{
	bop_panic("impl_acc_hdl_get");
}

void
atomic_dec_32(void)
{
	bop_panic("atomic_dec_32");
}

void
lwp_sema_trywait(void)
{
	bop_panic("lwp_sema_trywait");
}

void
anon_free_pages(void)
{
	bop_panic("anon_free_pages");
}

void
atomic_or_uint(void)
{
	bop_panic("atomic_or_uint");
}

void
mod_hash_reserve(void)
{
	bop_panic("mod_hash_reserve");
}

void
page_get_pagecnt(void)
{
	bop_panic("page_get_pagecnt");
}

void
atomic_or_long(void)
{
	bop_panic("atomic_or_long");
}

void
mod_hash_replace(void)
{
	bop_panic("mod_hash_replace");
}

void
atomic_cas_32(void)
{
	bop_panic("atomic_cas_32");
}

void
i_ddi_trigger_softint(void)
{
	bop_panic("i_ddi_trigger_softint");
}

void
exec_get_spslew(void)
{
	bop_panic("exec_get_spslew");
}

void
debug_enter(void)
{
	bop_panic("debug_enter");
}

void
pr_allstopped(void)
{
	bop_panic("pr_allstopped");
}

void
vfs_optionisset(void)
{
	bop_panic("vfs_optionisset");
}

void
anon_swap_free(void)
{
	bop_panic("anon_swap_free");
}

void
zfs_prop_to_name(void)
{
	bop_panic("zfs_prop_to_name");
}

void
dtrace_membar_producer(void)
{
	bop_panic("dtrace_membar_producer");
}

void
idmap_purge_cache(void)
{
	bop_panic("idmap_purge_cache");
}

void
segkmem_lpsetup(void)
{
	bop_panic("segkmem_lpsetup");
}

void
page_list_next(void)
{
	bop_panic("page_list_next");
}

void
ndi_fm_init(void)
{
	bop_panic("ndi_fm_init");
}

void
dtrace_gethrtime(void)
{
	bop_panic("dtrace_gethrtime");
}

void
vfs_makefsops(void)
{
	bop_panic("vfs_makefsops");
}

void
sosendfile64(void)
{
	bop_panic("sosendfile64");
}

void
prefetch_smap_w(void)
{
	bop_panic("prefetch_smap_w");
}

void
hat_getpagesize(void)
{
	bop_panic("hat_getpagesize");
}

void
cpu_intr_swtch_enter(void)
{
	bop_panic("cpu_intr_swtch_enter");
}

void
devfs_walk(void)
{
	bop_panic("devfs_walk");
}

void
vfs_hold(void)
{
	bop_panic("vfs_hold");
}

void
vfs_rele(void)
{
	bop_panic("vfs_rele");
}

void
vfs_sync(void)
{
	bop_panic("vfs_sync");
}

void
mod_hash_walk(void)
{
	bop_panic("mod_hash_walk");
}

void
mod_hash_find(void)
{
	bop_panic("mod_hash_find");
}

void
mod_hash_byid(void)
{
	bop_panic("mod_hash_byid");
}

void
hat_getattr(void)
{
	bop_panic("hat_getattr");
}

void
prefetch_page_r(void)
{
	bop_panic("prefetch_page_r");
}

void
page_destroy(void)
{
	bop_panic("page_destroy");
}

void
anon_unresvmem(void)
{
	bop_panic("anon_unresvmem");
}

void
kcage_tick(void)
{
	bop_panic("kcage_tick");
}

void
page_free(void)
{
	bop_panic("page_free");
}

void
page_find(void)
{
	bop_panic("page_find");
}

void
page_next(void)
{
	bop_panic("page_next");
}

void
page_lock(void)
{
	bop_panic("page_lock");
}

void
page_resv(void)
{
	bop_panic("page_resv");
}

void
fulword(void)
{
	bop_panic("fulword");
}

void
atomic_dec_uint(void)
{
	bop_panic("atomic_dec_uint");
}

void
i_mod_hash_find_nosync(void)
{
	bop_panic("i_mod_hash_find_nosync");
}

void
atomic_add_64(void)
{
	bop_panic("atomic_add_64");
}

void
atomic_add_32(void)
{
	bop_panic("atomic_add_32");
}

void
fuword8(void)
{
	bop_panic("fuword8");
}

void
fss_freebuf(void)
{
	bop_panic("fss_freebuf");
}

void
hat_memload_array_region(void)
{
	bop_panic("hat_memload_array_region");
}

void
hat_kpm_mapin(void)
{
	bop_panic("hat_kpm_mapin");
}

void
set_freemem(void)
{
	bop_panic("set_freemem");
}

void
page_subclaim(void)
{
	bop_panic("page_subclaim");
}

void
spec_getvnodeops(void)
{
	bop_panic("spec_getvnodeops");
}

void
anonmap_alloc(void)
{
	bop_panic("anonmap_alloc");
}

void
hat_thread_exit(void)
{
	bop_panic("hat_thread_exit");
}

void
anon_swap_restore(void)
{
	bop_panic("anon_swap_restore");
}

void
delete_mbind(void)
{
	bop_panic("delete_mbind");
}

void
mach_sysconfig(void)
{
	bop_panic("mach_sysconfig");
}

void
anon_copy_ptr(void)
{
	bop_panic("anon_copy_ptr");
}

void
kcage_cageout_init(void)
{
	bop_panic("kcage_cageout_init");
}

void
hat_dup_region(void)
{
	bop_panic("hat_dup_region");
}

void
anonmap_purge(void)
{
	bop_panic("anonmap_purge");
}

void
mutex_owner(void)
{
	bop_panic("mutex_owner");
}

void
anon_release(void)
{
	bop_panic("anon_release");
}

void
fss_changepset(void)
{
	bop_panic("fss_changepset");
}

void
fss_changeproj(void)
{
	bop_panic("fss_changeproj");
}

void
lwp_stk_init(void)
{
	bop_panic("lwp_stk_init");
}

void
lwp_stk_fini(void)
{
	bop_panic("lwp_stk_fini");
}

void
disp_lock_exit_high(void)
{
	bop_panic("disp_lock_exit_high");
}

void
anon_resvmem(void)
{
	bop_panic("anon_resvmem");
}

void
hat_free_end(void)
{
	bop_panic("hat_free_end");
}

void
lwp_pcb_exit(void)
{
	bop_panic("lwp_pcb_exit");
}

void
lwp_load(void)
{
	bop_panic("lwp_load");
}

void
page_relocate(void)
{
	bop_panic("page_relocate");
}

void
hat_dup(void)
{
	bop_panic("hat_dup");
}

void
hat_map(void)
{
	bop_panic("hat_map");
}

void
atomic_add_long_nv(void)
{
	bop_panic("atomic_add_long_nv");
}

void
hat_kpm_mapout(void)
{
	bop_panic("hat_kpm_mapout");
}

void
set_proc_post_sys(void)
{
	bop_panic("set_proc_post_sys");
}

void
e_ddi_copytodev(void)
{
	bop_panic("e_ddi_copytodev");
}

void
anon_array_exit(void)
{
	bop_panic("anon_array_exit");
}

void
lwp_sema_timedwait(void)
{
	bop_panic("lwp_sema_timedwait");
}

void
idmap_unreg_dh(void)
{
	bop_panic("idmap_unreg_dh");
}

void
set_idle_cpu(void)
{
	bop_panic("set_idle_cpu");
}

void
modgetsymname(void)
{
	bop_panic("modgetsymname");
}

void
gethrestime_lasttick(void)
{
	bop_panic("gethrestime_lasttick");
}

void
atomic_cas_uint(void)
{
	bop_panic("atomic_cas_uint");
}

void
mod_containing_pc(void)
{
	bop_panic("mod_containing_pc");
}

void
anonmap_free(void)
{
	bop_panic("anonmap_free");
}

void
upimutex_cleanup(void)
{
	bop_panic("upimutex_cleanup");
}

void
driver_active(void)
{
	bop_panic("driver_active");
}

void
lock_set_spl(void)
{
	bop_panic("lock_set_spl");
}

void
highbit(void)
{
	bop_panic("highbit");
}

void
cl_flk_state_transition_notify(void)
{
	bop_panic("cl_flk_state_transition_notify");
}

void
drv_usecwait(void)
{
	bop_panic("drv_usecwait");
}

void
page_list_concat(void)
{
	bop_panic("page_list_concat");
}

void
set_base_spl(void)
{
	bop_panic("set_base_spl");
}

void
ftrace_interrupt_disable(void)
{
	bop_panic("ftrace_interrupt_disable");
}

void
mod_hash_destroy(void)
{
	bop_panic("mod_hash_destroy");
}

void
impl_free_instance(void)
{
	bop_panic("impl_free_instance");
}

void
lwp_mutex_trylock(void)
{
	bop_panic("lwp_mutex_trylock");
}

void
page_num_pagesizes(void)
{
	bop_panic("page_num_pagesizes");
}

void
fsop_sync_by_kind(void)
{
	bop_panic("fsop_sync_by_kind");
}

void
intr_passivate(void)
{
	bop_panic("intr_passivate");
}

void
dcopy_alloc(void)
{
	bop_panic("dcopy_alloc");
}

void
valid_va_range(void)
{
	bop_panic("valid_va_range");
}

void
anon_set_ptr(void)
{
	bop_panic("anon_set_ptr");
}

void
ddi_get64(void)
{
	bop_panic("ddi_get64");
}

void
ddi_get32(void)
{
	bop_panic("ddi_get32");
}

void
ddi_get16(void)
{
	bop_panic("ddi_get16");
}

void
ddi_put64(void)
{
	bop_panic("ddi_put64");
}

void
ddi_put32(void)
{
	bop_panic("ddi_put32");
}

void
ddi_put16(void)
{
	bop_panic("ddi_put16");
}

void
sock_getfasync(void)
{
	bop_panic("sock_getfasync");
}

void
dtrace_interrupt_disable(void)
{
	bop_panic("dtrace_interrupt_disable");
}

void
lwp_freeregs(void)
{
	bop_panic("lwp_freeregs");
}

void
xcopyin_nta(void)
{
	bop_panic("xcopyin_nta");
}

void
i_ddi_mem_free(void)
{
	bop_panic("i_ddi_mem_free");
}

void
hat_page_setattr(void)
{
	bop_panic("hat_page_setattr");
}

void
page_get_shift(void)
{
	bop_panic("page_get_shift");
}

void
page_addclaim_pages(void)
{
	bop_panic("page_addclaim_pages");
}

void
ndi_fmc_entry_error_all(void)
{
	bop_panic("ndi_fmc_entry_error_all");
}

void
impl_setup_ddi(void)
{
	bop_panic("impl_setup_ddi");
}

void
mod_hash_insert(void)
{
	bop_panic("mod_hash_insert");
}

void
shutdown(void)
{
	bop_panic("shutdown");
}

void
mod_hash_cancel(void)
{
	bop_panic("mod_hash_cancel");
}

void
audit_anchorpath(void)
{
	bop_panic("audit_anchorpath");
}

void
i_convert_boot_device_name(void)
{
	bop_panic("i_convert_boot_device_name");
}

void
mod_hash_destroy_strhash(void)
{
	bop_panic("mod_hash_destroy_strhash");
}

void
dsl_prop_get(void)
{
	bop_panic("dsl_prop_get");
}

void
page_release(void)
{
	bop_panic("page_release");
}

void
vfs_list_unlock(void)
{
	bop_panic("vfs_list_unlock");
}

void
vfs_syncprogress(void)
{
	bop_panic("vfs_syncprogress");
}

void
__aeabi_llsr(void)
{
	bop_panic("__aeabi_llsr");
}

void
__aeabi_llsl(void)
{
	bop_panic("__aeabi_llsl");
}

void
cu_pg_update(void)
{
	bop_panic("cu_pg_update");
}

void
siron(void)
{
	bop_panic("siron");
}

void
panic_saveregs(void)
{
	bop_panic("panic_saveregs");
}

void
panic_savetrap(void)
{
	bop_panic("panic_savetrap");
}

void
turnstile_lookup(void)
{
	bop_panic("turnstile_lookup");
}

void
turnstile_stay_asleep(void)
{
	bop_panic("turnstile_stay_asleep");
}

void
ddi_modclose(void)
{
	bop_panic("ddi_modclose");
}

void
panic_quiesce_hw(void)
{
	bop_panic("panic_quiesce_hw");
}

void
panic_stopcpus(void)
{
	bop_panic("panic_stopcpus");
}

void
turnstile_wakeup(void)
{
	bop_panic("turnstile_wakeup");
}

void
mp_cpu_poweroff(void)
{
	bop_panic("mp_cpu_poweroff");
}

void
turnstile_block(void)
{
	bop_panic("turnstile_block");
}

void
ddi_modopen(void)
{
	bop_panic("ddi_modopen");
}

void
cpu_create_intrstat(void)
{
	bop_panic("cpu_create_intrstat");
}

void
mp_cpu_faulted_enter(void)
{
	bop_panic("mp_cpu_faulted_enter");
}

void
pg_plat_hw_shared(void)
{
	bop_panic("pg_plat_hw_shared");
}

void
cpupm_plat_domain_id(void)
{
	bop_panic("cpupm_plat_domain_id");
}

void
bp_color(void)
{
	bop_panic("bp_color");
}

void
pg_plat_cmt_policy(void)
{
	bop_panic("pg_plat_cmt_policy");
}

void
siron_poke_cpu(void)
{
	bop_panic("siron_poke_cpu");
}

void
mod_remove(void)
{
	bop_panic("mod_remove");
}

void
getpil(void)
{
	bop_panic("getpil");
}

void
panic_showtrap(void)
{
	bop_panic("panic_showtrap");
}

void
cpu_disable_intr(void)
{
	bop_panic("cpu_disable_intr");
}

void
setjmp(void)
{
	bop_panic("setjmp");
}

void
traceregs(void)
{
	bop_panic("traceregs");
}

void
unscalehrtime(void)
{
	bop_panic("unscalehrtime");
}

void
cpupm_plat_state_enumerate(void)
{
	bop_panic("cpupm_plat_state_enumerate");
}

void
mp_cpu_stop(void)
{
	bop_panic("mp_cpu_stop");
}

void
membar_sync(void)
{
	bop_panic("membar_sync");
}

void
membar_exit(void)
{
	bop_panic("membar_exit");
}

void
pg_plat_cpus_share(void)
{
	bop_panic("pg_plat_cpus_share");
}

void
pg_plat_hw_rank(void)
{
	bop_panic("pg_plat_hw_rank");
}

void
cpu_enable_intr(void)
{
	bop_panic("cpu_enable_intr");
}

void
mp_cpu_faulted_exit(void)
{
	bop_panic("mp_cpu_faulted_exit");
}

void
turnstile_change_pri(void)
{
	bop_panic("turnstile_change_pri");
}

void
mp_cpu_unconfigure(void)
{
	bop_panic("mp_cpu_unconfigure");
}

void
pg_plat_get_core_id(void)
{
	bop_panic("pg_plat_get_core_id");
}

void
get_cpu_mstate(void)
{
	bop_panic("get_cpu_mstate");
}

void
elfexec(void)
{
	bop_panic("elfexec");
}

void
pg_plat_hw_instance_id(void)
{
	bop_panic("pg_plat_hw_instance_id");
}

void
atomic_dec_ulong(void)
{
	bop_panic("atomic_dec_ulong");
}

void
atomic_cas_ulong(void)
{
	bop_panic("atomic_cas_ulong");
}

void
atomic_clear_long_excl(void)
{
	bop_panic("atomic_clear_long_excl");
}

void
mapexec_brand(void)
{
	bop_panic("mapexec_brand");
}

void
panic_trigger(void)
{
	bop_panic("panic_trigger");
}

void
cpu_delete_intrstat(void)
{
	bop_panic("cpu_delete_intrstat");
}

void
panic_dump_hw(void)
{
	bop_panic("panic_dump_hw");
}

void
atomic_inc_64(void)
{
	bop_panic("atomic_inc_64");
}

void
atomic_inc_32(void)
{
	bop_panic("atomic_inc_32");
}

void
panic_enter_hw(void)
{
	bop_panic("panic_enter_hw");
}

void
cpupm_plat_change_state(void)
{
	bop_panic("cpupm_plat_change_state");
}

void
mp_cpu_start(void)
{
	bop_panic("mp_cpu_start");
}

void
turnstile_exit(void)
{
	bop_panic("turnstile_exit");
}

void
mp_cpu_configure(void)
{
	bop_panic("mp_cpu_configure");
}

void
mach_cpu_pause(void)
{
	bop_panic("mach_cpu_pause");
}

void
kdi_siron(void)
{
	bop_panic("kdi_siron");
}

void
ld_ib_prop(void)
{
	bop_panic("ld_ib_prop");
}

void
mp_cpu_poweron(void)
{
	bop_panic("mp_cpu_poweron");
}

void
strplumb(void)
{
	bop_panic("strplumb");
}

void
consconfig(void)
{
	bop_panic("consconfig");
}

void
release_bootstrap(void)
{
	bop_panic("release_bootstrap");
}

void
cluster(void)
{
	bop_panic("cluster");
}

void
reset_syscall_args(void)
{
	bop_panic("reset_syscall_args");
}

void
halt(void)
{
	bop_panic("halt");
}

void
startup(void)
{
	bop_panic("startup");
}

void
segkmem_gc(void)
{
	bop_panic("segkmem_gc");
}

void
cbe_init_pre(void)
{
	bop_panic("cbe_init_pre");
}

void
cbe_init(void)
{
	bop_panic("cbe_init");
}

void
vm_init(void)
{
	bop_panic("vm_init");
}

void
vfs_mountroot(void)
{
	bop_panic("vfs_mountroot");
}

void
post_startup(void)
{
	bop_panic("post_startup");
}

void
start_other_cpus(void)
{
	bop_panic("start_other_cpus");
}

void
mod_uninstall_daemon(void)
{
	bop_panic("mod_uninstall_daemon");
}
void
dtrace_safe_synchronous_signal(void)
{
	bop_panic("dtrace_safe_synchronous_signal");
}

void
prstop(void)
{
	bop_panic("prstop");
}

void
prnotify(void)
{
	bop_panic("prnotify");
}

void
prnostep(void)
{
	bop_panic("prnostep");
}

void
sendsig(void)
{
	bop_panic("sendsig");
}

void
audit_core_start(void)
{
	bop_panic("audit_core_start");
}

void
dtrace_safe_defer_signal(void)
{
	bop_panic("dtrace_safe_defer_signal");
}

void
audit_core_finish(void)
{
	bop_panic("audit_core_finish");
}

void
reset(void)
{
	bop_panic("reset");
}

void
prom_enter_mon(void)
{
	bop_panic("prom_enter_mon");
}
