#!/bin/sh
# Run the test suite against the arm64 build inside an arm64 Linux VM
# (qemu-system-aarch64, Ubuntu 24.04 kernel, busybox initramfs). Works on any
# Linux host; needs qemu-system-arm, qemu-user-static, cpio, curl, openssl.
#   make cross-arm64 && test/vm.sh [test names...]
set -e
REPO=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$REPO/build/arm64/absurd}
VM=${VM_DIR:-$HOME/.cache/absurd-vm}
mkdir -p "$VM"
if [ ! -f "$VM/vmlinuz" ]; then
  ports=http://ports.ubuntu.com/ubuntu-ports/pool/main
  kpkg=linux-image-unsigned-6.8.0-71-generic_6.8.0-71.71_arm64.deb
  curl -fsS -o "$VM/k.deb" "$ports/l/linux/$kpkg"
  curl -fsS -o "$VM/bb.deb" "$ports/b/busybox/busybox-static_1.37.0-4ubuntu1_arm64.deb"
  (cd "$VM" && mkdir -p k bb && dpkg-deb -x k.deb k && dpkg-deb -x bb.deb bb &&
   cp k/boot/vmlinuz-* vmlinuz && cp bb/usr/bin/busybox busybox && rm -rf k bb k.deb bb.deb)
fi
W=$(mktemp -d); trap 'rm -rf "$W"; kill $QPID 2>/dev/null || true' EXIT
R=$W/root; mkdir -p $R/bin $R/proc $R/sys $R/dev $R/etc $R/tmp
cp "$VM/busybox" $R/bin/busybox
for a in sh mount ip sleep poweroff date; do ln -s busybox $R/bin/$a; done
cp "$BIN" $R/bin/absurd
python3 "$REPO/test/run.py" fixture $R/site
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout $R/etc/key.pem \
  -out $R/etc/cert.pem -days 2 -subj /CN=localhost 2>/dev/null
chmod 600 $R/etc/key.pem
cat > $R/etc/absurd.conf <<EOC
listen 18081
listen 18443 tls
tls_cert /etc/cert.pem
tls_key  /etc/key.pem
root /site
proxy /api/  10.0.2.2:18090
proxy /dead/ 10.0.2.2:18091
challenge /protected/
challenge_difficulty 12
header_timeout 3
upstream_timeout 2
# qemu's user-mode network takes ~0.3 s per forwarded connect: keep the
# connections of the many-connections test alive while the rest are opened
idle_timeout 300
EOC
cat > $R/init <<EOI
#!/bin/sh
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev
date -s @$(date +%s) >/dev/null
ip link set lo up; ip addr add 10.0.2.15/24 dev eth0; ip link set eth0 up; ip route add default via 10.0.2.2
ulimit -n 65536
/bin/absurd -c /etc/absurd.conf
echo "absurd exited with \$?"
poweroff -f
EOI
chmod +x $R/init
(cd $R && find . | cpio -o -H newc 2>/dev/null | gzip -1) > $W/initrd.gz
qemu-system-aarch64 -M virt -cpu max -smp 2 -m 1024 -kernel "$VM/vmlinuz" -initrd $W/initrd.gz \
  -append "console=ttyAMA0 quiet panic=-1" -nographic -no-reboot \
  -netdev user,id=n,hostfwd=tcp:127.0.0.1:18081-:18081,hostfwd=tcp:127.0.0.1:18443-:18443 \
  -device virtio-net-pci,netdev=n > $W/console.log 2>&1 &
QPID=$!
for i in $(seq 1 120); do grep -q "listening on https" $W/console.log 2>/dev/null && break; sleep 1; done
grep absurd: $W/console.log || { cat $W/console.log; exit 1; }
if [ -n "$VM_CMD" ]; then sh -c "$VM_CMD"; exit; fi   # e.g. VM_CMD="curl -s localhost:18081/"
CONNS=${CONNS:-200} EXPECT_PEER=10.0.2.2 EXPECT_UPHOST=10.0.2.2:18090 CONFIG_CHECK_BINARY="qemu-aarch64-static $BIN" \
  python3 "$REPO/test/run.py" --external "$@"
