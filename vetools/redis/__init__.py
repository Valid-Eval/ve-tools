def get_metrics_for_rsmq_queue(rsmq, queue):
    attrs = rsmq.getQueueAttributes(qname=queue).execute()
    metrics = {
        'totalrecv': attrs['totalrecv'],
        'totalsent': attrs['totalsent'],
        'msgs': attrs['msgs'],
        'hiddenmsgs': attrs['hiddenmsgs']
    }
    return metrics


def get_metrics_for_rsmq(rsmq):
    queues = rsmq.listQueues().execute()
    metrics = {}
    for queue in queues:
        metrics[queue] = get_metrics_for_rsmq_queue(rsmq, queue)
    return metrics


def get_metrics_for_sidekiq_queue(redis, queue):
    count = redis.llen("queue:%s" % queue)
    metrics = {'msgs': count}
    return metrics


def get_metrics_for_sidekiq(redis):
    queues = redis.smembers("queues")
    metrics = {}
    for queue in queues:
        metrics[queue] = get_metrics_for_sidekiq_queue(redis, queue)
    return metrics


def get_metrics_for_bull_queue(redis, queue):
    count = redis.llen("bull:%s:wait" % queue)
    recv = redis.get("bull:%s:id" % queue)
    metrics = {'msgs': count, 'totalrecv': recv}
    return metrics


def get_metrics_for_bull(redis):
    queues = redis.keys("bull:*:id")
    queues = [q.split(":")[1] for q in queues]
    metrics = {}
    for queue in queues:
        metrics[queue] = get_metrics_for_bull_queue(redis, queue)
    return metrics
