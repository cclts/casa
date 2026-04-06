1. build
```
make
```
2. run
```
make run 2>&1 | stdbuf -oL tee trace.log
```
3. show dir
```
tree -I "*.o|*.mod|*.sum"
```