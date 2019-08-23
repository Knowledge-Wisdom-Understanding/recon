#!/usr/bin/env python3

import multiprocessing
import subprocess
import shlex

from multiprocessing.pool import ThreadPool


def call_proc(cmd):
    """ This runs in a separate thread. """
    #subprocess.call(shlex.split(cmd))  # This will block until cmd finishes
    p = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = p.communicate()
    return (out, err)


pool = ThreadPool(multiprocessing.cpu_count())
results = []
for i in range(1, 20):
    arguments += str(i) + "_image.jpg "
    results.append(pool.apply_async(call_proc, ("./combine" + arguments, )))

# Close the pool and wait for each running task to complete
pool.close()
pool.join()
for result in results:
    out, err = result.get()
    print("out: {} err: {}".format(out, err))
subprocess.call("./merge_resized_images")