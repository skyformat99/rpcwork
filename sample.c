#include "event.h"
#include "work.h"

struct _work_queue_t {
    struct work_queue *fixed_work;
    struct work_queue *dynamic_work;
    struct work_queue *ordered_work;
} work_queue_list;

static void *work_loop(void *arg) {
	(void)arg;
	while (true) {
		event_loop(-1);
	}
	return NULL;
}

int main() {  
    pthread_t thread;
    int ret = 0;
	if (init_event(4096) < 0) {
		sd_err("failed to add epoll event ");
		return -1;
	}
	if (init_work_queue()) {
		return -1;
    }
    work_queue_list.fixed_work = create_fixed_work_queue("WayFixed", 4);
	if (!work_queue_list.fixed_work) {
		sd_err("failed to create work queue");
		return ret;
	}

    work_queue_list.dynamic_work = create_dynamic_work_queue("WayDynamic");
	if (!work_queue_list.dynamic_work) {
		sd_err("failed to create work queue");
		return ret;
	}

    work_queue_list.ordered_work = create_ordered_work_queue("WayOrdered");
	if (!work_queue_list.ordered_work) {
		sd_err("failed to create work queue");
		return ret;
	}
    
    pthread_create(&thread, NULL, work_loop, NULL);
    pthread_join(thread, NULL);
    return 0;
}
