# Test fixture: tautological and dead code patterns

def always_true():
    if True:
        print("always runs")

def always_false():
    if False:
        print("never runs")

def unreachable_code():
    return 42
    print("this never runs")

def self_compare(x):
    if x == x:
        return True

def bool_compare(x):
    if x == True:
        return "yes"
    if x == False:
        return "no"

def good_code(x):
    if x > 0:
        return "positive"
    return "non-positive"
