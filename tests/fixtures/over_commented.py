# Test fixture: over-commenting patterns

def overly_commented_function(x, y):
    # Initialize the result variable
    result = 0
    # Loop through the range
    for i in range(x):
        # Check if i is even
        if i % 2 == 0:
            # Add i to result
            result += i
        # Increment the counter
        # Check if we should continue
    # Return the result
    return result

def clean_function(x, y):
    """Sum even numbers up to x."""
    return sum(i for i in range(x) if i % 2 == 0)
