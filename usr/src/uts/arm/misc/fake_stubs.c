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
p0(void)
{
	bop_panic("p0");
}

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
kdi_dvec_mod_loaded(void)
{
	bop_panic("kdi_dvec_mod_loaded");
}

void
kdi_flush_caches(void)
{
	bop_panic("kdi_flush_caches");
}

void
cons_polledio(void)
{
	bop_panic("cons_polledio");
}

void
kcred(void)
{
	bop_panic("kcred");
}

void
kvseg(void)
{
	bop_panic("kvseg");
}

void
panic(char *panicstr)
{
	bop_panic("panic");
}

void
callb_generic_cpr(void)
{
	bop_panic("callb_generic_cpr");
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
callb_add(void)
{
	bop_panic("callb_add");
}

void
last_module_id(void)
{
	bop_panic("last_module_id");
}

void
callb_delete(void)
{
	bop_panic("callb_delete");
}

void
kmem_alloc(void)
{
	bop_panic("kmem_alloc");
}

void
vmem_alloc(void)
{
	bop_panic("vmem_alloc");
}

void
kmem_ready(void)
{
	bop_panic("kmem_ready");
}

void
sema_init(void)
{
	bop_panic("sema_init");
}

void
heaptext_arena(void)
{
	bop_panic("heaptext_arena");
}

void
maxclsyspri(void)
{
	bop_panic("maxclsyspri");
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
modules(void)
{
	bop_panic("modules");
}

void
SHA1Final(void)
{
	bop_panic("SHA1Final");
}

void
ksyms_lock(void)
{
	bop_panic("ksyms_lock");
}

void
initargs(void)
{
	bop_panic("initargs");
}

void
initname(void)
{
	bop_panic("initname");
}

void
kdi_dtrace_get_state(void)
{
	bop_panic("kdi_dtrace_get_state");
}

void
default_path(void)
{
	bop_panic("default_path");
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
vmem_create(void)
{
	bop_panic("vmem_create");
}

void
fop_close(void)
{
	bop_panic("fop_close");
}

void
heap_arena(void)
{
	bop_panic("heap_arena");
}

void
vn_openat(void)
{
	bop_panic("vn_openat");
}

void
kdi_pwrite(void)
{
	bop_panic("kdi_pwrite");
}

void
cv_signal(void)
{
	bop_panic("cv_signal");
}

int boothowto;

void
kdi_dvec_mod_unloading(void)
{
	bop_panic("kdi_dvec_mod_unloading");
}

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
kmem_zalloc(void)
{
	bop_panic("kmem_zalloc");
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
sema_p(void)
{
	bop_panic("sema_p");
}

void
sema_v(void)
{
	bop_panic("sema_v");
}

void
thread_exit(void)
{
	bop_panic("thread_exit");
}

void
ksyms_arena(void)
{
	bop_panic("ksyms_arena");
}

void
vmem_contains(void)
{
	bop_panic("vmem_contains");
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
cv_destroy(void)
{
	bop_panic("cv_destroy");
}

void
kdi_vtop(void)
{
	bop_panic("kdi_vtop");
}

void
threadp(void)
{
	bop_panic("threadp");
}

void
stubs_end(void)
{
	bop_panic("stubs_end");
}

void
vmem_free(void)
{
	bop_panic("vmem_free");
}

void
kmem_free(void)
{
	bop_panic("kmem_free");
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
segkmem_alloc(void)
{
	bop_panic("segkmem_alloc");
}

void
vn_open(void)
{
	bop_panic("vn_open");
}

void
vn_rdwr(void)
{
	bop_panic("vn_rdwr");
}

void
vn_rele(void)
{
	bop_panic("vn_rele");
}

void
sema_destroy(void)
{
	bop_panic("sema_destroy");
}

void
rw_enter(void)
{
	bop_panic("rw_enter");
}

void
kdi_dtrace_set(void)
{
	bop_panic("kdi_dtrace_set");
}

void
vprintf(void)
{
	bop_panic("vprintf");
}

void
fop_getattr(void)
{
	bop_panic("fop_getattr");
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
thread_create(void)
{
	bop_panic("thread_create");
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
assfail(void)
{
	bop_panic("assfail");
}

void
mutex_owned(void)
{
	bop_panic("mutex_owned");
}

/*
 * prom_printf and co. are supposed to come from genunix. Further rather than
 * reinvent the wheel here, we should move uts/intel/promif to psm/non1275/ and
 * make a common set of code here rather than just reinvent everything.
 */
void
prom_printf(void)
{
	bop_panic("prom_prinf");
}

void
main(void)
{
	bop_panic("main!");
}

void
binit(void)
{
        bop_panic("binit");
}

void
finit(void)
{
        bop_panic("finit");
}

void
sys_init(void)
{
        bop_panic("sys_init");
}

void
clock_realtime_init(void)
{
        bop_panic("clock_realtime_init");
}

void
dnlc_init(void)
{
        bop_panic("dnlc_init");
}

void
deadman_init(void)
{
        bop_panic("deadman_init");
}

void
flk_init(void)
{
        bop_panic("flk_init");
}

void
clock_tick_mp_init(void)
{
        bop_panic("clock_tick_mp_init");
}

void
schedctl_init(void)
{
        bop_panic("schedctl_init");
}

void
serializer_init(void)
{
        bop_panic("serializer_init");
}

void
anon_init(void)
{
        bop_panic("anon_init");
}

void
clock_timer_init(void)
{
        bop_panic("clock_timer_init");
}

void
physmem(void)
{
        bop_panic("physmem");
}

void
callout_mp_init(void)
{
        bop_panic("callout_mp_init");
}

void
as_init(void)
{
        bop_panic("as_init");
}

void
softcall_init(void)
{
        bop_panic("softcall_init");
}

void
space_init(void)
{
        bop_panic("space_init");
}

void
ftrace_init(void)
{
        bop_panic("ftrace_init");
}

void
sys_classfuncs(void)
{
        bop_panic("sys_classfuncs");
}

void
cmn_err(void)
{
        bop_panic("cmn_err");
}

void
fdb_init(void)
{
        bop_panic("fdb_init");
}

void
cu_init(void)
{
        bop_panic("cu_init");
}

void
strinit(void)
{
        bop_panic("strinit");
}

void
ttyinit(void)
{
        bop_panic("ttyinit");
}

void
cyclic_mp_init(void)
{
        bop_panic("cyclic_mp_init");
}

void
vmem_size(void)
{
        bop_panic("vmem_size");
}

void
vfsinit(void)
{
        bop_panic("vfsinit");
}

void
segvn_init(void)
{
        bop_panic("segvn_init");
}

void
pvn_init(void)
{
        bop_panic("pvn_init");
}

void
system_taskq_init(void)
{
        bop_panic("system_taskq_init");
}

void
cpu_seq_tbl_init(void)
{
        bop_panic("cpu_seq_tbl_init");
}

void
clock_highres_init(void)
{
        bop_panic("clock_highres_init");
}
