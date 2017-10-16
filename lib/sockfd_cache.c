
/*
 * The sockfd cache provides us long TCP connections connected to the nodes
 * in the cluster to accelerator the data transfer, which has the following
 * characteristics:
 *    0 dynamically allocated/deallocated at node granularity.
 *    1 cached fds are multiplexed by all threads.
 *    2 each session (for e.g, forward_write_obj_req) can grab one fd at a time.
 *    3 if there isn't any FD available from cache, use normal connect_to() and
 *      close() internally.
 *    4 FD are named by IP:PORT uniquely, hence no need of resetting at
 *      membership change.
 *    5 the total number of FDs is scalable to massive nodes.
 *    6 total 3 APIs: sheep_{get,put,del}_sockfd().
 *    7 support dual connections to a single node.
 */

#include <pthread.h>

#include "sockfd_cache.h"
#include "work.h"
#include "rbtree.h"
#include "util.h"
#include "net.h"



struct sockfd_cache {
	struct rb_root root;
	struct sd_rw_lock lock;
	int count;
};

static struct sockfd_cache sockfd_cache = {
	.root = RB_ROOT,
	.lock = SD_RW_LOCK_INITIALIZER,
};

/*
 * Suppose request size from Guest is 512k, then 4M / 512k = 8, so at
 * most 8 requests can be issued to the same sheep object. Based on this
 * assumption, '8' would be efficient for servers that only host 2~4
 * Guests.
 *
 * This fd count will be dynamically grown when the idx reaches watermark which
 * is calculated by FDS_WATERMARK
 */
#define FDS_WATERMARK(x) ((x) * 3 / 4)
#define DEFAULT_FDS_COUNT	8

/* How many FDs we cache for one node */
static int fds_count = DEFAULT_FDS_COUNT;

struct sockfd_cache_fd {
	int fd;
	uatomic_bool in_use;
};

struct sockfd_cache_entry {
	struct rb_node rb;
	struct node_id nid;
	struct sockfd_cache_fd *fds;
};

static inline int node_id_cmp(const struct node_id *node1,
			      const struct node_id *node2)
{
	int cmp = memcmp(node1->addr, node2->addr, sizeof(node1->addr));
	if (cmp != 0)
		return cmp;

	return intcmp(node1->port, node2->port);
}


static int sockfd_cache_cmp(const struct sockfd_cache_entry *a,
			    const struct sockfd_cache_entry *b)
{
	return node_id_cmp(&a->nid, &b->nid);
}

static struct sockfd_cache_entry *
sockfd_cache_insert(struct sockfd_cache_entry *new)
{
	return rb_insert(&sockfd_cache.root, new, rb, sockfd_cache_cmp);
}

static struct sockfd_cache_entry *sockfd_cache_search(const struct node_id *nid)
{
	struct sockfd_cache_entry key = { .nid = *nid };

	return rb_search(&sockfd_cache.root, &key, rb, sockfd_cache_cmp);
}

static inline int get_free_slot(struct sockfd_cache_entry *entry)
{
	int idx = -1, i;

	for (i = 0; i < fds_count; i++) {
		if (!uatomic_set_true(&entry->fds[i].in_use))
			continue;
		idx = i;
		break;
	}
	return idx;
}

/*
 * Grab a free slot of the node and inc the refcount of the slot
 *
 * If no free slot available, this typically means we should use short FD.
 */
static struct sockfd_cache_entry *sockfd_cache_grab(const struct node_id *nid,
						    int *ret_idx)
{
	struct sockfd_cache_entry *entry;

	sd_read_lock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	if (!entry) {
        if (nid->is_socket) {
            sd_debug("failed node %s", nid->unixpath);
        } else {
		    sd_debug("failed node %s", addr_to_str(nid->addr, nid->port));
        }
		goto out;
	}

	*ret_idx = get_free_slot(entry);
	if (*ret_idx == -1)
		entry = NULL;
out:
	sd_rw_unlock(&sockfd_cache.lock);
	return entry;
}

static inline bool slots_all_free(struct sockfd_cache_entry *entry)
{
	int i;
	for (i = 0; i < fds_count; i++)
		if (uatomic_is_true(&entry->fds[i].in_use))
			return false;
	return true;
}

static inline void destroy_all_slots(struct sockfd_cache_entry *entry)
{
	int i;
	for (i = 0; i < fds_count; i++)
		if (entry->fds[i].fd != -1)
			close(entry->fds[i].fd);
}

static void free_cache_entry(struct sockfd_cache_entry *entry)
{
	free(entry->fds);
	free(entry);
}

/*
 * Destroy all the Cached FDs of the node
 *
 * We don't proceed if some other node grab one FD of the node. In this case,
 * the victim node will finally find itself talking to a dead node and call
 * sockfd_cache_del() to delete this node from the cache.
 */
static bool sockfd_cache_destroy(const struct node_id *nid)
{
	struct sockfd_cache_entry *entry;

	sd_write_lock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	if (!entry) {
		sd_debug("It is already destroyed");
		goto false_out;
	}

	if (!slots_all_free(entry)) {
		sd_debug("Some victim still holds it");
		goto false_out;
	}

	rb_erase(&entry->rb, &sockfd_cache.root);
	sd_rw_unlock(&sockfd_cache.lock);

	destroy_all_slots(entry);
	free_cache_entry(entry);

	return true;
false_out:
	sd_rw_unlock(&sockfd_cache.lock);
	return false;
}

//static void sockfd_cache_add_nolock(const struct node_id *nid)
//{
//	struct sockfd_cache_entry *new = xmalloc(sizeof(*new));
//	int i;

//	new->fds = xzalloc(sizeof(struct sockfd_cache_fd) * fds_count);
//	for (i = 0; i < fds_count; i++)
//		new->fds[i].fd = -1;

//	memcpy(&new->nid, nid, sizeof(struct node_id));
//	if (sockfd_cache_insert(new)) {
//		free_cache_entry(new);
//		return;
//	}
//	sockfd_cache.count++;

//}

/* Add group of nodes to the cache */
//void sockfd_cache_add_group(const struct rb_root *nroot)
//{
//	struct sd_node *n;

//	sd_write_lock(&sockfd_cache.lock);
//	rb_for_each_entry(n, nroot, rb) {
//		sockfd_cache_add_nolock(&n->nid);
//	}
//	sd_rw_unlock(&sockfd_cache.lock);
//}

/* Add one node to the cache means we can do caching tricks on this node */
void sockfd_cache_add(const struct node_id *nid)
{
	struct sockfd_cache_entry *new;
	int n, i;

	sd_write_lock(&sockfd_cache.lock);
	new = xmalloc(sizeof(*new));
	new->fds = xzalloc(sizeof(struct sockfd_cache_fd) * fds_count);
	for (i = 0; i < fds_count; i++)
		new->fds[i].fd = -1;

	memcpy(&new->nid, nid, sizeof(struct node_id));
	if (sockfd_cache_insert(new)) {
		free_cache_entry(new);
		sd_rw_unlock(&sockfd_cache.lock);
		return;
	}
	sd_rw_unlock(&sockfd_cache.lock);
	n = uatomic_add_return(&sockfd_cache.count, 1);
	sd_debug("%s, count %d", addr_to_str(nid->addr, nid->port), n);

}

static uatomic_bool fds_in_grow;
static int fds_high_watermark = FDS_WATERMARK(DEFAULT_FDS_COUNT);

static struct work_queue *grow_wq = NULL;

static void do_grow_fds(struct work *work)
{
	struct sockfd_cache_entry *entry;
	int old_fds_count, new_fds_count, new_size, i;

	sd_debug("%d", fds_count);
	sd_write_lock(&sockfd_cache.lock);
	old_fds_count = fds_count;
	new_fds_count = fds_count * 2;
	new_size = sizeof(struct sockfd_cache_fd) * fds_count * 2;
	rb_for_each_entry(entry, &sockfd_cache.root, rb) {
		entry->fds = xrealloc(entry->fds, new_size);
		for (i = old_fds_count; i < new_fds_count; i++) {
			entry->fds[i].fd = -1;
			uatomic_set_false(&entry->fds[i].in_use);
		}
	}

	fds_count *= 2;
	fds_high_watermark = FDS_WATERMARK(fds_count);
	sd_rw_unlock(&sockfd_cache.lock);

}

static void grow_fds_done(struct work *work)
{
	sd_debug("fd count has been grown into %d", fds_count);
	uatomic_set_false(&fds_in_grow);
	free(work);
}

static inline void check_idx(int idx)
{
	struct work *w;

	if (idx <= fds_high_watermark)
		return;
	if (!uatomic_set_true(&fds_in_grow))
		return;

	w = xmalloc(sizeof(*w));
	w->fn = do_grow_fds;
	w->done = grow_fds_done;
	queue_work(grow_wq, w);
}

/* Add the node back if it is still alive */
static inline int revalidate_node(const struct node_id *nid)
{
	int fd;
    if (nid->is_socket) {
	    fd = connect_to_socket((const char *)nid->unixpath);
    } else {
	    fd = connect_to((const char *)nid->addr, nid->port);
    }
	if (fd < 0)
		return false;
	close(fd);
	sockfd_cache_add(nid);
	return true;
}

/* Try to create/get cached IO connection. If failed, fallback to non-IO one */
static struct sockfd *sockfd_cache_get_long(const struct node_id *nid)
{
	struct sockfd_cache_entry *entry;
	struct sockfd *sfd;
#ifndef HAVE_ACCELIO
	const uint8_t *addr = nid->addr;
	int fd, idx = -1, port =  nid->port;
#else
	bool use_io = false;
	const uint8_t *addr = nid->addr;
	int fd, idx = -1, port = nid->port;
#endif
grab:
	entry = sockfd_cache_grab(nid, &idx);
	if (!entry) {
		/*
		 * The node is deleted, but someone asks us to grab it.
		 * The nid is not in the sockfd cache but probably it might be
		 * still alive due to broken network connection or was just too
		 * busy to serve any request that makes other nodes deleted it
		 * from the sockfd cache. In such cases, we need to add it back.
		 */
		if (!revalidate_node(nid))
			return NULL;

		goto grab;
	}

	check_idx(idx);
	/* Create a new cached connection for this node */
    if (nid->is_socket) {
        if (entry->fds[idx].fd != -1) {
    		sd_debug("%s, idx %d", nid->unixpath, idx);
    		goto out;
	    }
        sd_debug("create cache connection unixpath(%s) idx %d", nid->unixpath, idx);
	    fd = connect_to_socket((const char *)nid->unixpath);
    } else {
    	if (entry->fds[idx].fd != -1) {
    		sd_debug("%s, idx %d", addr_to_str(addr, port), idx);
    		goto out;
	    }
        sd_debug("create cache connection %s idx %d", addr_to_str(addr, port), idx);
	    fd = connect_to((const char *)addr, port);
    }
    if (fd < 0) {
		uatomic_set_false(&entry->fds[idx].in_use);
		return NULL;
	}
	entry->fds[idx].fd = fd;
out:
	sfd = xmalloc(sizeof(*sfd));
	sfd->fd = entry->fds[idx].fd;
	sfd->idx = idx;


	return sfd;
}

static void sockfd_cache_put_long(const struct node_id *nid, int idx)
{
	const uint8_t *addr = nid->addr;
	int port = nid->port;
	struct sockfd_cache_entry *entry;
    
    if (nid->is_socket) {
        sd_debug("%s idx %d", nid->unixpath, idx);
    } else {
        sd_debug("%s idx %d", addr_to_str(addr, port), idx);
    }
	
	sd_read_lock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	if (entry)
		uatomic_set_false(&entry->fds[idx].in_use);
	sd_rw_unlock(&sockfd_cache.lock);
}

static void sockfd_cache_close(const struct node_id *nid, int idx)
{
	const uint8_t *addr =  nid->addr;
	int port = nid->port;
	struct sockfd_cache_entry *entry;
    
    if (nid->is_socket) {
        sd_debug("%s idx %d", nid->unixpath, idx);
    } else {
        sd_debug("%s idx %d", addr_to_str(addr, port), idx);
    }

	sd_write_lock(&sockfd_cache.lock);
	entry = sockfd_cache_search(nid);
	if (entry) {
		close(entry->fds[idx].fd);
		entry->fds[idx].fd = -1;
		uatomic_set_false(&entry->fds[idx].in_use);
	}
	sd_rw_unlock(&sockfd_cache.lock);
}

/*
 * Create work queue for growing fds.
 * Before this function called, growing cannot be done.
 */
int sockfd_init(void)
{
	if(!grow_wq){
		grow_wq = create_ordered_work_queue("sockfd_grow");

		if (!grow_wq) {
			sd_err("error at creating workqueue for sockfd growth");
			return -1;
		}
	}
	return 0;
}

/*
 * Return a sockfd connected to the node to the caller
 *
 * Try to get a 'long' FD as best, which is cached and never closed. If no FD
 * available, we return a 'short' FD which is supposed to be closed by
 * sockfd_cache_put().
 *
 * ret_idx is opaque to the caller, -1 indicates it is a short FD.
 */
struct sockfd *sockfd_cache_get(const struct node_id *nid)
{
	struct sockfd *sfd;
	int fd;

	sfd = sockfd_cache_get_long(nid);
	if (sfd) {
		return sfd;
    }
    
	/* Fallback on a non-io connection that is to be closed shortly */
    if (nid->is_socket) {
	    fd = connect_to_socket((const char *)nid->unixpath);
    } else {
        fd = connect_to((const char *)nid->addr, nid->port);
    }
    if (fd < 0) {
        return NULL;
    }
	sfd = xmalloc(sizeof(*sfd));
	sfd->idx = -1;
	sfd->fd = fd;
	sd_debug("%d", fd);
	return sfd;
}

/*
 * Release a sockfd connected to the node, which is acquired from
 * sockfd_cache_get()
 *
 * If it is a long FD, just decrease the refcount to make it available again.
 * If it is a short FD, close it.
 */
void sockfd_cache_put(const struct node_id *nid, struct sockfd *sfd)
{
	if (sfd->idx == -1) {
		sd_debug("%d", sfd->fd);
		close(sfd->fd);
		free(sfd);

		return;
	}
	sockfd_cache_put_long(nid, sfd->idx);
	free(sfd);
}

/* Delete all sockfd connected to the node, when node is crashed. */
void sockfd_cache_del_node(const struct node_id *nid)
{
	int n;

	if (!sockfd_cache_destroy(nid))
		return;

	n = uatomic_sub_return(&sockfd_cache.count, 1);
	sd_debug("%s, count %d", addr_to_str(nid->addr, nid->port), n);
}

/*
 * Delete a sockfd connected to the node.
 *
 * If it is a long FD, de-refcount it and try to destroy all the cached FDs of
 * this node in the cache.
 * If it is a short FD, just close it.
 */
void sockfd_cache_del(const struct node_id *nid, struct sockfd *sfd)
{
	if (sfd->idx == -1) {
		sd_debug("%d", sfd->fd);
		close(sfd->fd);
		free(sfd);
		return;
	}

	sockfd_cache_close(nid, sfd->idx);
	sockfd_cache_del_node(nid);
	free(sfd);
}

