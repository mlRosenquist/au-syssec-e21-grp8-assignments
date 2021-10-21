from hashlib import sha512
password_hash = "dce5d86a6b6e2ddc6fb0733532bcbdd9d83f66e71b1e00ac8dfcf6bf12b8b6acd446b0cd8c76e4b0713e91e71713288fe9db2243393250bec877cfb567aaaf8d"
def login() -> bool:
    print("Enter master password:")
    correct_pass = False
    max_incorrect_attempts = 3
    attempts = 0
    while not correct_pass and attempts < max_incorrect_attempts:
        input_password = input()
        if(sha512(input_password.encode()).digest().hex() == password_hash):
            correct_pass = True
        else:
            print("Incorrect password, try again")
            attempts += 1
    return correct_pass
#Secret password: !YouWillNeverGuessMySecretPassword!
