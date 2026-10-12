# Renders assets/demo.gif with VHS (https://github.com/charmbracelet/vhs).
# Start the stack on a fresh database first, so the ledger starts at #1:
#   docker compose down -v && docker compose up -d --build --wait
#   vhs scripts/demo.tape
# The Demo workflow (.github/workflows/demo.yml) does this in CI.

Output assets/demo.gif

Require bash
Require curl
Require jq

Set Shell "bash"
# Tall enough that the whole run (about 44 rows) fits without scrolling.
Set FontSize 16
Set Width 1200
Set Height 1010
Set Padding 24
Set TypingSpeed 45ms
Set Theme "Catppuccin Mocha"

Type "bash scripts/demo.sh"
Sleep 600ms
Enter
Wait+Screen@90s /Done\./
Sleep 4s
