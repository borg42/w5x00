
#ifndef __QUEUE_H__
#define __QUEUE_H__

typedef struct _skb_node {
	struct list_head list;
	struct sk_buff *skb;
} SKB_NODE;

SKB_NODE *alloc_skb_node(void);
void free_skb_node(SKB_NODE *p);
void push_skb(SKB_NODE *p);
SKB_NODE *pop_skb(void);

#endif
