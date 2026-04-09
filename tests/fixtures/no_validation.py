# Test fixture: missing input validation patterns

def send_email(recipient, subject, body, cc_list):
    """Send an email without any input validation."""
    message = f"To: {recipient}\nSubject: {subject}\n\n{body}"
    for cc in cc_list:
        message += f"\nCC: {cc}"
    return message

def calculate(x, y, operation):
    """Calculate with validation."""
    if not isinstance(operation, str):
        raise ValueError("operation must be a string")
    if operation == "add":
        return x + y
    return None

def _private_helper(data):
    """Private functions should not be flagged."""
    return data * 2
