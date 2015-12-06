import os

def find_git_dir():
    """ Return the absolute path of the .git directory """
    gitdir = os.getenv('GIT_DIR')
    if not gitdir:
        HOME=os.getenv('HOME')
        ROOT='/'
        cwd = os.getcwd()
        while True:
            if '.git' in os.listdir(cwd):   # found
                gitdir = os.path.join(cwd, '.git')
                break
            elif cwd in (HOME, ROOT):   # no more to try
                break
            else:                       # go up
                cwd, junk = os.path.split(cwd)
    return gitdir


def get_last_pushed(branch):
    """ Return the a tuple of positions of the branch and
    its cipher counterpart when they had been pushed recently.
    If they had never been pushed, return 40 zeros.

    Format of the pushed record file:

        branch-name:plaintext-commit:ciphertext-commit

    """
    filename      = 'CIPHER_MAP'
    gitdir        = find_git_dir()
    pushed_record = os.path.join(gitdir, filename)
    tag           = branch + ':'
    empty         = '0' * 40
    result        = [empty, empty]
    try:
        for line in open(pushed_record):
            if line.startswith(tag):
                result = line.split(':')[1:]
                break
    except:
        pass

    return result
