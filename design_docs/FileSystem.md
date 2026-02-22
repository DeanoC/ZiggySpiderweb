## FileSystem
The agents will see a unified file system, that in fact may be across multiple machines.
The intent is to allow the to cooperate with the users local file system and cloud storage, in the same way the work with a nodes workspce.

To do this the idea is to use a FUSE filesystem, that is built on top of WebSocket connections to the remote nodes mixed in with local node filesystem.

Each node will have its project filesystems mapped to a workspace subtree.

0) Design targets
   Transport: WSS (WebSocket over TLS)

Encoding: MsgPack or CBOR

Identity: stable node_id (u64) per file/dir, not path

Handles: stable handle_id (u64) from OPEN

Directory reads: READDIR_PLUS (names + attrs in one hit)

Consistency: close-to-open + optional invalidation events

Cross-node rename: return EXDEV

1) Frame envelope (request/response)
   Every WS message is one MsgPack/CBOR map.

Request envelope
{
    "t": "req",
    "id": u32,          // request id from client
    "op": "READDIRP",   // operation name
    "node": u64,        // optional: node_id target
    "h": u64,           // optional: handle_id target
    "a": { ... }        // args map (operation-specific)
}
Response envelope
{
    "t": "res",
    "id": u32,           // matches request
    "ok": true|false,
    "err": { "no": i32, "msg": str }?,   // only if ok=false
    "r": { ... }?        // result map
}
Event envelope (server push)
{
    "t": "evt",
    "op": "INVAL",
    "a": { ... }
}
Errno mapping: err.no uses Linux errno integers (ENOENT=2, EIO=5, EXDEV=18, etc.). Client returns -errno to FUSE.

2) Common data structures
   Attr (what FUSE needs for getattr)
   Keep it minimal but correct:

Attr = {
"id": u64,        // node_id (redundant but handy)
"k": u8,          // kind: 1=file, 2=dir, 3=symlink (optional)
"m": u32,         // mode bits (e.g. 0o100644)
"n": u32,         // nlink (usually 1 for files, 2+ for dirs)
"u": u32,         // uid (often map to local uid)
"g": u32,         // gid
"sz": u64,        // size in bytes
"at": i64,        // atime ns since epoch (or seconds if you prefer, but be consistent)
"mt": i64,        // mtime ns
"ct": i64,        // ctime ns
"gen": u64        // generation/version number (for cache coherency)
}
DirEntryPlus
Entry = {
"name": str,
"attr": Attr
}
Node reference
You’ll have two “node” concepts:

Workspace node: “a”, “b”, “c” (remote machine endpoint)

Filesystem node_id: inode-like ID inside that endpoint

In the client, treat each mounted workspace subtree as a “provider root” that maps:

/mnt/workspace/a -> remote endpoint connection + exported root node_id

3) Handshake + discovery (HELLO / MOUNTS)
   HELLO (client -> server)
   op="HELLO", a={
   "proto": 1,
   "client": { "name":"ziggystarclaw", "ver":"0.3.x" },
   "want": { "events": true, "readdirp": true }
   }
   HELLO response (server -> client)
   r={
   "proto": 1,
   "node": { "name":"Node-A", "os":"windows|linux|mac", "ver":"1.0.0" },
   "caps": {
   "readdirp": true,
   "symlink": false,
   "xattr": false,
   "locks": false,
   "case_sensitive": true|false,
   "max_read": 1048576,
   "max_write": 1048576
   }
   }
   EXPORTS / MOUNTS (client asks what roots are exported)
   op="EXPORTS"
   Response:

r={
"exports":[
{ "name":"work", "root": u64, "ro": false, "desc":"D:\\Work" },
{ "name":"repo", "root": u64, "ro": true,  "desc":"/home/repo" }
]
}
In your workspace router FS, you decide which export becomes /a root.

4) Filesystem operations
   LOOKUP (resolve child name under a directory node_id)
   op="LOOKUP", node=<parent_id>, a={ "name":"foo.txt" }
   Response:

r={ "attr": Attr }
GETATTR
op="GETATTR", node=<id>
Response:

r={ "attr": Attr }
READDIR_PLUS (the star of the show ⭐)
Supports pagination via a cookie. (Cookie can be u64 offset, or opaque bytes.)

op="READDIRP", node=<dir_id>, a={ "cookie": u64, "max": u32 }
Response:

r={
"ents":[ Entry, Entry, ... ],
"next": u64,        // next cookie
"eof": true|false,
"dir_gen": u64      // optional: generation for the directory listing itself
}
Note: Always include "." and ".." entries client-side or server-side, but be consistent.

OPEN
op="OPEN", node=<file_id>, a={ "flags": u32 } // POSIX open flags subset
Response:

r={
"h": u64,           // handle_id
"caps": { "rd":true, "wr":false },
"gen": u64          // file generation at open time
}
READ
op="READ", h=<handle_id>, a={ "off": u64, "len": u32 }
Response:

r={ "data": <bytes>, "eof": bool }
CLOSE
op="CLOSE", h=<handle_id>
Response:

r={}
5) Writes (v2, but define now so you don’t paint yourself in a corner)
   CREATE (create and open)
   op="CREATE", node=<dir_id>, a={
   "name": "new.txt",
   "mode": u32,
   "flags": u32
   }
   Response:

r={ "attr": Attr, "h": u64 }
WRITE
op="WRITE", h=<handle_id>, a={ "off": u64, "data": <bytes> }
Response:

r={ "n": u32 } // bytes written
TRUNCATE
op="TRUNCATE", node=<file_id>, a={ "sz": u64 }
RENAME (same endpoint only)
op="RENAME", a={
"old_parent": u64, "old_name": "a.txt",
"new_parent": u64, "new_name": "b.txt"
}
If it crosses workspace subtrees, client should short-circuit with EXDEV.

6) Optional but very useful: invalidation events
   If the node can watch local FS changes:

Invalidate file attrs/content
t="evt", op="INVAL", a={ "node": u64, "what": "attr|data|all", "gen": u64 }
Invalidate a directory listing
t="evt", op="INVAL_DIR", a={ "dir": u64, "dir_gen": u64 }
Client reacts by dropping caches for that node/dir.

This is how you get “live-ish” without TTL spam. 🪄

7) Mapping to FUSE callbacks (Linux libfuse mental model)
   Below is the “translation table” your FUSE daemon should follow.

Mount layout
FUSE root / contains:

a/, b/, c/ (synthetic directories representing endpoints)

.status, .ctl (virtual files)

Each endpoint dir has an internal node_id = exported root on that node.

getattr(path)
Goal: return struct stat

Strategy
For / and top-level synthetic dirs, return synthetic attrs (mode dir, size 0).

For /a/..., resolve via provider:

Use path-to-node cache if available (more below)

Otherwise LOOKUP chain from root_id through each path component, or maintain a directory entry cache from READDIRP.

Protocol calls:

Prefer cached Attr from READDIRP or LOOKUP

If missing/stale: GETATTR(node_id)

Return:

st_mode, st_size, times, etc.

st_ino: use node_id (but must be unique per entire mount; combine endpoint id + node_id if needed)

readdir(path)
Goal: return names (and ideally attrs, but FUSE API varies)

Strategy
Identify dir node_id

Call READDIRP(dir_id, cookie, max)

Feed entries back to FUSE

Protocol calls:

READDIRP (possibly multiple times until filled)

Caching:

Cache dir listing (names + attrs) keyed by (endpoint, dir_id, dir_gen) or TTL

Store Entry.attr in attr cache so getattr doesn’t trigger storms

open(path)
Goal: produce a file handle fh

Strategy
Resolve node_id (using cache + LOOKUP chain)

Call OPEN(node_id, flags)

Store returned handle_id in fi->fh (or your equivalent)

Protocol calls:

OPEN

read(path, size, offset, fh)
Goal: return bytes

Strategy
Use handle_id from fh

Use read-cache: chunk requests into aligned blocks (e.g. 256 KiB)

Call READ(handle, off, len) as needed

Protocol calls:

READ

release/flush (close)
Goal: close handle

Protocol calls:

CLOSE(handle_id)

8) Caching rules that make grep -R happy
   A) Attr cache
   Key: (endpoint, node_id) -> Attr + expires_at + gen

Update from: LOOKUP, GETATTR, READDIRP

TTL: 1–5 seconds (or longer if you have invalidations)

B) Dir entry cache
Key: (endpoint, dir_id) -> map { name -> Attr } + dir_gen + expiry

Populate from READDIRP

Used for:

fast LOOKUP of children without network (if entry exists)

avoiding getattr storms

C) Read cache (block cache)
Key: (endpoint, handle_id, block_index) -> bytes

Block size: 256 KiB is a good starting point

Eviction: LRU with size cap

D) Negative cache
Key: (endpoint, parent_dir_id, name) -> ENOENT with short TTL (0.5–1s)

Helps when tools probe for build artifacts repeatedly.

9) How to represent node_id globally (avoid inode collisions)
   If each endpoint has its own u64 node_id, combine them:

global_ino = hash64(endpoint_uuid || node_id)
Or simpler:

give each endpoint a small u16 index

global_ino = (u64(endpoint_index) << 48) | (node_id & ((1<<48)-1))

Just ensure you don’t collide across endpoints.

10) A minimal “v1 schema” list (copy/paste into your spec)
    Required ops (v1 read-only):

HELLO, EXPORTS

LOOKUP, GETATTR, READDIRP

OPEN, READ, CLOSE

Optional v1:

STATFS

INVAL, INVAL_DIR events

v2 writes:

CREATE, WRITE, TRUNCATE, UNLINK, MKDIR, RMDIR, RENAME
