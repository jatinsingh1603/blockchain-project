import http.server, threading, functools, json, sys
from playwright.sync_api import sync_playwright

ROOT = "/home/claude/apkguard-web/public"
handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=ROOT)
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8765), handler)
threading.Thread(target=srv.serve_forever, daemon=True).start()

results = {}
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1300, "height": 900})
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
    pg.goto("http://127.0.0.1:8765/")
    pg.wait_for_function("document.getElementById('chainStatus').textContent.includes('block')", timeout=30000)
    pg.click("#useDemo")
    pg.wait_for_selector("#facts:not([hidden])")
    results["pkg"] = pg.text_content("#fPkg")
    pg.click("#verifyBtn"); pg.wait_for_timeout(1200)
    results["before_register"] = pg.text_content("#verdict small")
    pg.click("#regBtn"); pg.wait_for_timeout(1500)
    print("DBG", pg.inner_text("#ledger"), "|", pg.inner_text("#verdict"), errs)
    pg.click(".voteBtn[data-b=B1]"); pg.wait_for_timeout(400)
    pg.click("#verify2"); pg.wait_for_timeout(1200)
    results["one_vote"] = pg.text_content("#verdict small")
    pg.click(".voteBtn[data-b=B2]"); pg.wait_for_timeout(400)
    pg.click("#verify2"); pg.wait_for_timeout(1200)
    results["two_votes"] = pg.text_content("#verdict")
    pg.screenshot(path="/home/claude/apkguard-web/test/shot_ok.png", full_page=True)
    for a in ["build", "key", "repack", "outsider", "floor", "revoke"]:
        pg.click(f".atk[data-a={a}]"); pg.wait_for_timeout(1500)
        results[a] = pg.text_content(f".atk[data-a={a}] >> xpath=.. >> .res")
    pg.screenshot(path="/home/claude/apkguard-web/test/shot_attacks.png", full_page=True)
    results["ledger_rows"] = pg.locator("#ledger tr").count()
    pg.set_viewport_size({"width": 390, "height": 844})
    pg.screenshot(path="/home/claude/apkguard-web/test/shot_mobile.png", full_page=False)
    results["errors"] = errs
    b.close()
print(json.dumps(results, indent=1))
