import os
import subprocess

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


def run_for_output(cmd):
    """ Run the cmd, return the stdout as a list of lines
    as well as the stat of the cmd (True or False)
    """
    stat, output = subprocess.getstatusoutput(cmd)
    if stat == 0:
        return True, output.split('\n')
    else:
        return False, []


def reachable(start_commit, end_commit):
    """ Check if start_commit is reachable from the end_commit """
    cmd = 'git merge-base %s..%s' % (start_commit, end_commit)
    stat, output = run_for_output(cmd)
    if stat:
        base = output[0]
        cmd = 'git rev-parse --verify %s' % start_commit
        stat, output = run_for_output(cmd)
        if stat and output[0] == base:
            return True
    return False


def find_all_commits(start_commit, end_commit):
    """ Return a list of commits' SHA1s that based on the
    start_commit (excluded) up to the end_commit (included),
    the start_commit shall be reachable from the end_commit
    unless start_commit is 40 zeros, or exception will raise.
    On errer, return an empty list.
    """
    empty = '0' * 40
    if start_commit == empty:
        rev_range = end_commit
    else:
        if not reachable(start_commit, end_commit):
            msg = '%s is not reachable from %s' % (start_commit, end_commit)
            raise Exception(msg)
        else:
            rev_range = '%s..%s' % (start_commit, end_commit)
    cmd = 'git log --pretty=format:"%h" ' + rev_range
    stat, commits = run_for_output(cmd)
    return commits
