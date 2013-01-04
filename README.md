# Leknarf fork of bluepill

Adds experimental features to bluepill. You almost certainly want the stock version of bluepill from [arya/bluepill](https://github.com/arya/bluepill).

# Additions

## Monitors all process descendants

The stock version of bluepill can monitor a process's children. This version will recursively search for a process's grand-children, great-grand-children, etc..

This is useful if you are running resque-pool, which has three levels of processes: the pool manager, the workers, and the worker children (which process the actual jobs).

## Uses top for CPU usage stats

The stock version of bluepill polls `ps` to get CPU usage stats. This returns the average CPU usage since a process was launched. See [this ticket](https://github.com/arya/bluepill/issues/110) for a discussion.

This version uses top for CPU usage stats instead.




