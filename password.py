import re

# Password policy rules
MIN_LENGTH = 8
MAX_LENGTH = 32
REQUIRE_UPPERCASE = True
REQUIRE_LOWERCASE = True
REQUIRE_DIGIT = True
REQUIRE_SPECIAL_CHAR = True

def is_password_secure(password):
    # Check length
    if len(password) < MIN_LENGTH or len(password) > MAX_LENGTH:
        return False
    
    # Check uppercase requirement
    if REQUIRE_UPPERCASE and not re.search(r"[A-Z]", password):
        return False
    
    # Check lowercase requirement
    if REQUIRE_LOWERCASE and not re.search(r"[a-z]", password):
        return False
    
    # Check digit requirement
    if REQUIRE_DIGIT and not re.search(r"\d", password):
        return False
    
    # Check special character requirement
    if REQUIRE_SPECIAL_CHAR and not re.search(r"[!@#$%^&*()-_=+{}\[\]|\\;:'\",.<>/?`~]", password):
        return False
    
    # Password meets all requirements
    return True

def main():
    password = input("Enter a password: ")
    
    if is_password_secure(password):
        print("Password meets the secure policy.")
    else:
        print("Password does not meet the secure policy.")

if __name__ == "__main__":
    main()