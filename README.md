# DNF Plugin for Performance Metrics

This plug-in will record performance metrics for DNF and store them in JSON files under `/var/log/dnf/perfmetrics`.

## Installing from Source

From the git checkout:

```
$ mkdir build
$ cmake -B build .
$ make -C build
$ sudo make -C build install
```
