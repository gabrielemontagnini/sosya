# The README GIF. Record with the images already pulled and an LLM key in the environment,
# with `sosya` on PATH:
#
#     vhs docs/demo.tape
#
# Needs vhs, ttyd and ffmpeg. On hosts that block unprivileged user namespaces (recent Ubuntu),
# Chromium's sandbox cannot start: set VHS_NO_SANDBOX=true. The range it builds keeps running:
# stop it with `sosya down`. Measured on 2026-11-22: 21 s, 175 KB.

Output docs/demo.gif

Set Shell bash
Set Width 1200
Set Height 760
Set FontSize 18
Set Padding 24
Set Framerate 12
Set TypingSpeed 25ms
Set Theme "Builtin Dark"
Set CursorBlink false

Hide
Type `export PS1='$ ' && cd "$(mktemp -d)" && clear`
Enter
Sleep 500ms
Show

Type `sosya new "Struts2 app in a DMZ, passwordless Redis reachable only from the web server"`
Sleep 300ms
Enter
Wait+Screen@60s /Start this range/
Sleep 1.5s
Enter
Wait+Screen@120s /ready /
Sleep 1.5s

Type "sosya shell"
Enter
Wait+Screen@30s /root.attacker/
Sleep 500ms
Type `curl -s -o /dev/null -w 'web:8080 answers HTTP %{http_code}\n' http://web:8080`
Enter
Wait+Screen@30s /answers HTTP/
Sleep 2.5s
