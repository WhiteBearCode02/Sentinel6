# Intentionally vulnerable fixture. Never execute this file.
import subprocess
def evaluate(user_input):
    return eval(user_input)
def command(user_input):
    subprocess.run(user_input, shell=True)
