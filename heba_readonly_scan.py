#!/usr/bin/env python3
# HEBA OMEGA — أداة قراءة فقط لمسح سجلات Modbus/TCP لجهاز واحد (Read-Only Register Profiler)
# المالك: Mahmoud El-Sisi — للاستخدام الهندسي المدني بإذن كتابي من مالك المحطة فقط.
# الضمانات البرمجية: (1) لا ترسل إلا وظيفتَي القراءة 03 و04 — أي وظيفة أخرى ترفعها الأداة قبل الإرسال.
# (2) تتصل بعنوان واحد تحدده أنت، ولا تمسح شبكة ولا تبحث عن أجهزة أخرى. (3) معدل طلبات محدود.
# (4) لا تعمل دون العلم --i-have-owner-permission. (5) لا تكتب شيئاً على الجهاز مطلقاً.
# الناتج: ملف CSV بسلوك كل سجل (ثابت/ثنائي/عدّاد/تناظري). الأسماء الحقيقية للنقاط تأتي من جدول Tags المصدّر من برنامج المحطة.
import argparse, csv, socket, struct, sys, time

READ_ONLY_FUNCS = (3, 4)  # Read Holding Registers / Read Input Registers فقط

def req(sock, tid, unit, fc, addr, cnt, timeout):
    if fc not in READ_ONLY_FUNCS:
        raise SystemExit("رُفض: وظيفة غير قراءة (%r)" % fc)
    sock.settimeout(timeout)
    sock.sendall(struct.pack(">HHHBBHH", tid, 0, 6, unit, fc, addr, cnt))
    hdr = b""
    while len(hdr) < 7:
        c = sock.recv(7 - len(hdr))
        if not c: raise ConnectionError("أُغلق الاتصال")
        hdr += c
    ln = struct.unpack(">H", hdr[4:6])[0] - 1
    body = b""
    while len(body) < ln:
        c = sock.recv(ln - len(body))
        if not c: raise ConnectionError("أُغلق الاتصال")
        body += c
    if body[0] & 0x80:
        return None  # استثناء (عنوان غير صالح غالباً)
    n = body[1]
    return list(struct.unpack(">%dH" % (n // 2), body[2:2 + n]))

def read_block(sock, st, unit, fc, addr, cnt, timeout, delay):
    st["tid"] = (st["tid"] + 1) & 0xFFFF; st["n"] += 1
    if st["n"] > st["max"]: raise SystemExit("بلغت الحد الأقصى لعدد الطلبات (%d)" % st["max"])
    time.sleep(delay)
    return req(sock, st["tid"], unit, fc, addr, cnt, timeout)

def scan_area(sock, st, unit, fc, start, count, block, timeout, delay):
    out = {}
    a = start; end = start + count
    while a < end:
        n = min(block, end - a)
        r = read_block(sock, st, unit, fc, a, n, timeout, delay)
        if r is None and n > 1:  # قسّم الكتلة لتجاوز العناوين غير الصالحة
            sub = max(1, n // 4)
            for b in range(a, a + n, sub):
                m = min(sub, a + n - b)
                rr = read_block(sock, st, unit, fc, b, m, timeout, delay)
                if rr is not None:
                    for i, v in enumerate(rr): out[b + i] = v
        elif r is not None:
            for i, v in enumerate(r): out[a + i] = v
        a += n
    return out

def classify(vals):
    d = set(vals)
    if len(d) == 1: return "constant"
    if d <= {0, 1}: return "binary"
    ch = sum(1 for i in range(1, len(vals)) if vals[i] != vals[i - 1])
    inc = all(vals[i] >= vals[i - 1] for i in range(1, len(vals)))
    if inc and ch >= 2: return "counter"
    return "analog"

def main():
    p = argparse.ArgumentParser(description="Read-only Modbus/TCP register profiler (single host)")
    p.add_argument("--host", required=True); p.add_argument("--port", type=int, default=502); p.add_argument("--unit", type=int, default=1)
    p.add_argument("--start", type=int, default=0); p.add_argument("--count", type=int, default=1000)
    p.add_argument("--block", type=int, default=100); p.add_argument("--samples", type=int, default=12); p.add_argument("--interval", type=float, default=1.0)
    p.add_argument("--delay", type=float, default=0.05, help="تأخير بين الطلبات (ث)"); p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--max-requests", type=int, default=20000); p.add_argument("--out", default="heba-registers.csv")
    p.add_argument("--i-have-owner-permission", action="store_true", help="أقر بأن لدي إذناً كتابياً من مالك المحطة بالقراءة فقط")
    a = p.parse_args()
    if not a.i_have_owner_permission: sys.exit("لن أعمل دون إقرارك بالإذن: أضف --i-have-owner-permission")
    if not (1 <= a.block <= 125 and 1 <= a.count <= 65536 and 1 <= a.samples <= 600 and a.delay >= 0.01): sys.exit("قيم خارج الحدود المسموحة")
    st = {"tid": 0, "n": 0, "max": a.max_requests}
    sock = socket.create_connection((a.host, a.port), timeout=a.timeout)
    hist = {}
    try:
        for s in range(a.samples):
            for fc, name in ((3, "holding"), (4, "input")):
                vals = scan_area(sock, st, a.unit, fc, a.start, a.count, a.block, a.timeout, a.delay)
                for addr, v in vals.items(): hist.setdefault((name, addr), []).append(v)
            print("عيّنة %d/%d — طلبات: %d" % (s + 1, a.samples, st["n"]), file=sys.stderr)
            if s + 1 < a.samples: time.sleep(a.interval)
    finally:
        sock.close()
    with open(a.out, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f); w.writerow(["area", "address", "min", "max", "distinct", "last", "class"])
        for (area, addr), vals in sorted(hist.items(), key=lambda x: (x[0][0], x[0][1])):
            w.writerow([area, addr, min(vals), max(vals), len(set(vals)), vals[-1], classify(vals)])
    print("تم: %d سجلاً → %s (قراءة فقط، %d طلباً)" % (len(hist), a.out, st["n"]), file=sys.stderr)

if __name__ == "__main__":
    main()
