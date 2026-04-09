# Test fixture: unused variable patterns

def unused_assignment():
    x = 10
    y = 20
    return x

def all_used():
    x = 10
    y = 20
    return x + y

def underscore_ok():
    _ = some_function()
    return True
