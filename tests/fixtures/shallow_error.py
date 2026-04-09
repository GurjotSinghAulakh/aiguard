# Test fixture: shallow error handling patterns

def bad_bare_except():
    try:
        result = 1 / 0
    except:
        pass

def bad_broad_except():
    try:
        data = open("file.txt").read()
    except Exception:
        pass

def bad_silent_except():
    try:
        value = int("abc")
    except ValueError:
        pass

def good_specific_except():
    try:
        value = int("abc")
    except ValueError as e:
        print(f"Invalid input: {e}")
        raise
