def load_seed_pools(seed_file_path):
    tags, events, js, others = [], [], [], []

    try:
        with open(seed_file_path, "r", encoding="utf-8") as f:
            for line in f:
                s = line.strip()
                if not s: continue

                low = s.lower()

                if low.startswith("tag:"):
                    tags.append(s[4:])
                elif low.startswith("event:"):
                    events.append(s[6:])
                elif low.startswith("js:"):
                    js.append(s[3:])
                else:
                    others.append(s)

    except:
        tags = ["<img", "<svg", "<script"]
        events = ["onerror=", "onload=", "onclick="]
        js = ["console.log(1)", "alert(1)"]

    return {"tags": tags, "events": events, "js": js, "others": others}
