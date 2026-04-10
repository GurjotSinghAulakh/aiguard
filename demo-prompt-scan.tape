Output demo-prompt-scan.gif

Set Shell bash
Set FontSize 14
Set Width 1300
Set Height 850
Set WindowBar Colorful
Set Theme "Catppuccin Mocha"
Set TypingSpeed 30ms
Set Padding 20

# Scene 1: Show the malicious prompt file
Type "# People blindly trust AI agent prompts & skills..."
Enter
Sleep 1500ms
Type "# Let's look at a 'helpful' coding assistant prompt:"
Enter
Sleep 1500ms
Type "cat tests/fixtures/demo_malicious.md"
Enter
Sleep 5s

# Clear
Hide
Type "clear"
Enter
Show
Sleep 300ms

# Scene 2: Scan the malicious file
Type "# AIGuard can now scan .md files for hidden threats"
Enter
Sleep 1500ms
Type "python3 -m aiguard scan tests/fixtures/demo_malicious.md"
Enter
Sleep 8s

# Clear
Hide
Type "clear"
Enter
Show
Sleep 300ms

# Scene 3: Scan a safe prompt — no false positives
Type "# A safe prompt file passes clean — zero false positives"
Enter
Sleep 1500ms
Type "python3 -m aiguard scan tests/fixtures/safe_prompt.md"
Enter
Sleep 4s

# Clear
Hide
Type "clear"
Enter
Show
Sleep 300ms

# Scene 4: Show all 14 rules
Type "# 14 detectors: 10 for code + 4 for prompt security"
Enter
Sleep 1500ms
Type "python3 -m aiguard list-rules"
Enter
Sleep 6s

Sleep 2s
