
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include "queue.h"

static LIST_HEAD(tx_skb);

SKB_NODE *alloc_skb_node(void)
{
	SKB_NODE *p = kmalloc(sizeof(SKB_NODE), GFP_KERNEL);

	return p;
}

void free_skb_node(SKB_NODE *p)
{
	kfree(p);
}

void push_skb(SKB_NODE *p)
{
	list_add_tail(&(p->list), &tx_skb);
}

SKB_NODE *pop_skb(void)
{
	struct list_head *head;

	if(list_empty(&tx_skb))
	{
		return NULL;
	}

	head = tx_skb.next;
	list_del(head);
	
	return list_entry(head, SKB_NODE, list);
}
