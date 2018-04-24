from cx_Freeze import setup, Executable

base = None

executables = [Executable("crypto_dec.py", base=base)]

packages = []
options = {
    'build_exe': {
        'packages':packages,
    },
}

setup(
    name = "SecurePreferences Decryptor",
    options = options,
    version = "0.1",
    description = 'Decrypts preferences files generated using SecurePreferences library on android.',
    executables = executables
)
