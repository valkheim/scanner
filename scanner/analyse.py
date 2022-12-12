import dataclasses
import subprocess
import typing as T

def run_process(args: T.List, write: T.Optional[str] = None, stdout: T.Union[T.BinaryIO, int] = subprocess.PIPE, stderr : T.Union[T.BinaryIO, int] = subprocess.PIPE, **kwargs: T.Any):
    p = subprocess.Popen(args, universal_newlines=True, close_fds=False,
    stdout=stdout, stderr=stderr, **kwargs)
    o, e = p.communicate(write)
    return p.returncode, o, e

def check_command(command: str) -> bool:
    args = command.split(" ")
    status, out, err = run_process(args)
    return status == 0

        
def analyse(filepath: str):
    print("analyse ", filepath)
    # passer le filepath a chaque script dans un dir de bin.
    # prévoir un script d'install genre installer des symlinks de md5sum etc
    # recup le nom du script pour creer le fichier
