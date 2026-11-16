# Long exposure merge: host tests

Host builds of the `z8longexp` engine (no camera, no emulator needed). They need a real Z8 NEF (FX, L, 14-bit lossless).

```sh
SRC=../../z8longexp/src
# 1. Encoder exactness: decode a NEF with nef.c, re-encode with lexp_enc.c, compare the strip byte for byte
clang -O2 -w -I$SRC -o rt roundtrip.c $SRC/nef.c $SRC/lexp_enc.c
./rt DSC_0001.NEF            # expect "mismatch -1"

# 2. Whole job on a POSIX platform: <root>/A and <root>/B stand for the two cards
clang -O2 -g -w -I$SRC -o hj host_job.c
mkdir -p root/A/DCIM/100NCZ_8 root/B/DCIM
./hj root make DSC_0001.NEF A/DCIM/100NCZ_8 10 5 1000 1 10   # 5 noisy frames, consecutive shutter counts, 10 s apart
./hj root make DSC_0001.NEF A/DCIM/100NCZ_8 40 2 2000 7 200  # 2 frames 200 s apart: must not be grouped
./hj root run                                                # psm_camera_job in "merge all" mode
./hj root check root/A/DCIM/100NCZ_8/DSC_0010_AVG.NEF root/A/DCIM/100NCZ_8/DSC_001[0-4].NEF   # expect 0 differing samples
```

`H_ALLOC_LIMIT=<bytes>` limits the host heap to exercise the smaller band sizes. A second `run` must report status 18
(no new series).
