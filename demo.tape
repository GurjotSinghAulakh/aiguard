Output demo.gif

Set Shell bash
Set FontSize 15
Set Width 1200
Set Height 750
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms
Set Padding 20

# Scan a single file
Type "python3 -m aiguard scan tests/fixtures/shallow_error.py"
Enter
Sleep 4s

# Clear
Hide
Type "clear"
Enter
Show
Sleep 300ms

# Scan full directory
Type "python3 -m aiguard scan tests/fixtures/"
Enter
Sleep 6s

# Clear
Hide
Type "clear"
Enter
Show
Sleep 300ms

# Diff mode
Type "# Only scan changed lines — zero noise on existing code"
Enter
Sleep 1s
Type "python3 -m aiguard scan --diff HEAD"
Enter
Sleep 3s

# Clear
Hide
Type "clear"
Enter
Show
Sleep 300ms

# List all rules
Type "python3 -m aiguard list-rules"
Enter
Sleep 4s

Sleep 2s
