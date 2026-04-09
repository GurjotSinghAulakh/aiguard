# Test fixture: copy-paste duplication patterns

def process_users(users):
    """Process a list of users."""
    results = []
    for user in users:
        if user.get("active"):
            name = user.get("name", "Unknown")
            email = user.get("email", "")
            results.append({"name": name, "email": email, "type": "user"})
    return results

def process_admins(admins):
    """Process a list of admins."""
    results = []
    for admin in admins:
        if admin.get("active"):
            name = admin.get("name", "Unknown")
            email = admin.get("email", "")
            results.append({"name": name, "email": email, "type": "admin"})
    return results

def completely_different():
    """This should not match the above."""
    import math
    return math.sqrt(42) + math.pi
