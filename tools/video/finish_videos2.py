"""Mac side, v2: make each partially recovered video playable by skipping damaged seconds instead of truncating.

usage: python3 finish_videos2.py LIST.tsv NAS_DEST_DIR WORKDIR > finish2.jsonl
LIST.tsv lines: rel<TAB>nas_source_path   (source = moov-repaired copy if one exists, else the partial file)
Per file: pull -> full decode check -> if bad: drop the time ranges of frames whose NAL framing is broken
(extended to the next sync frame) and splice the rest losslessly -> re-check; any remaining decode failure
at time t cuts [t-0.5, t+2] and repeats (max 6 rounds). Falls back to a plain trim. Results go to
NAS_DEST_DIR/rel (never overwriting).
"""
import json, os, re, shlex, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import movsamples as ms

lst, dest_dir, work = sys.argv[1:4]
SSH = ["ssh", "-o", "BatchMode=yes", os.environ.get("NAS_SSH", "USER@NAS_IP")]
os.makedirs(work, exist_ok=True)


def check(path):
    out = subprocess.run([os.path.join(HERE, "checkvideo"), path], capture_output=True, text=True).stdout
    return out.split("\t")[0]


def fail_time(c):
    t = [float(x) for x in re.findall(r"to ([0-9.]+)s FAILED", c)]
    return min(t) if t else None


def duration(c):
    m = re.search(r"duration=([0-9.]+)s", c)
    return float(m.group(1)) if m else None


def keep_from_drop(drop, total):
    keep, cur = [], 0.0
    for s, e in sorted(drop):
        if s > cur + 0.05:
            keep.append((cur, min(s, total)))
        cur = max(cur, e)
    if total > cur + 0.05:
        keep.append((cur, total))
    return keep


def splice(src, dst, keep):
    if os.path.exists(dst):
        os.unlink(dst)
    args = [os.path.join(HERE, "splicevideo"), src, dst] + ["%.3f-%.3f" % k for k in keep]
    r = subprocess.run(args, capture_output=True, text=True)
    return os.path.exists(dst) and r.stdout.strip().startswith("OK")


for line in open(lst, encoding="utf-8"):
    rel, src = line.rstrip("\n").split("\t")
    ext = os.path.splitext(rel)[1]
    res = {"rel": rel}
    a, b = os.path.join(work, "a" + ext), os.path.join(work, "b" + ext)
    try:
        for p in (a, b):
            if os.path.exists(p):
                os.unlink(p)
        with open(a, "wb") as f:
            subprocess.run(SSH + ["sudo -n cat " + shlex.quote(src)], stdout=f, check=True)
        c0 = check(a)
        total = duration(c0)
        res.update(check=c0[:200], duration=total)
        final = None
        if c0.startswith("OK"):
            final, res["status"], res["kept"] = a, "PLAYABLE_FULL", total
        elif total:
            try:
                drop = [tuple(x) for x in ms.bad_time_ranges(a)[0]]
            except Exception:
                drop = []
            try:
                segs = ms.segment_time_ranges(a)
            except Exception:
                segs = []
            cur = a
            for rnd in range(int(os.environ.get("ROUNDS", "7"))):
                keep = keep_from_drop(drop, total)
                if not keep or not splice(a, b, keep):
                    break
                c = check(b)
                if c.startswith("OK"):
                    final = b
                    res.update(status="PLAYABLE_SPLICED", kept=round(sum(e - s for s, e in keep), 2),
                               dropped=[[round(s, 2), round(e, 2)] for s, e in drop], rounds=rnd + 1)
                    break
                t = fail_time(c)
                if t is None:
                    break
                # map failure time in the spliced output back to the source timeline
                acc = 0.0
                for s, e in keep:
                    if t <= acc + (e - s):
                        t_src = s + (t - acc)
                        break
                    acc += e - s
                else:
                    t_src = keep[-1][1]
                span = next((g for g in segs if g[0] - 2.0 <= t_src <= g[1] + 2.0 and g not in drop), None)
                if span:  # failure inside an encrypted segment: its recovered bytes are suspect, skip all of it
                    drop.append(span)
                else:
                    drop.append((max(0.0, t_src - 0.5), t_src + float(os.environ.get("SKIP", "2.0"))))
            if final is None:  # plain trim fallback
                t = fail_time(c0)
                if t and t > 1.0:
                    if splice(a, b, [(0.0, t - 0.15)]) and check(b).startswith("OK"):
                        final = b
                        res.update(status="PLAYABLE_TRIMMED", kept=round(t - 0.15, 2))
        if final is None:
            res["status"] = res.get("status") or "UNREADABLE"
        else:
            dest = os.path.join(dest_dir, rel)
            cmd = "sudo -n mkdir -p %s && sudo -n sh -c %s" % (
                shlex.quote(os.path.dirname(dest)), shlex.quote("set -o noclobber; cat > " + shlex.quote(dest)))
            with open(final, "rb") as f:
                subprocess.run(SSH + [cmd], stdin=f, check=True)
    except Exception as e:
        res["status"] = "ERR"
        res["err"] = str(e)[:200]
    print(json.dumps(res, ensure_ascii=False))
    sys.stdout.flush()
