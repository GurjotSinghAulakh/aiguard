# Test fixture: placeholder code patterns

def just_pass():
    pass

def just_ellipsis():
    ...

def not_implemented():
    raise NotImplementedError("TODO: implement this")

def has_todo():
    x = 1
    # TODO implement the actual logic
    return x

# FIXME: this is broken
def fixme_function():
    return None

# This function is fine
def actual_implementation():
    return [i * 2 for i in range(10)]
