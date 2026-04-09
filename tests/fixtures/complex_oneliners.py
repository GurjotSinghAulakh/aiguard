# Test fixture: complex one-liner patterns

def nested_comprehension():
    return [[j for j in range(i) if j % 2 == 0] for i in range(10) if i > 3]

def chained_ternary(x):
    return "a" if x > 10 else "b" if x > 5 else "c" if x > 0 else "d"

def simple_comprehension():
    return [i * 2 for i in range(10)]

def complex_lambda():
    fn = lambda x: (lambda y: y ** 2 + x)(x + 1) if x > 0 else (lambda y: y - x)(x - 1)
    return fn
