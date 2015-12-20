import os, sys
import hashlib, zlib
from subprocess import Popen, PIPE, getstatusoutput

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
    """ Return a tuple of positions of the branch and its
    cipher counterpart when they had been pushed recently.
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


def get_status_text_output(cmd):
    """ Run the cmd, return the stdout as a list of lines
    as well as the stat of the cmd (True or False), content
    of the stdout will be decoded.
    """
    stat, output = getstatusoutput(cmd)
    if stat == 0:
        return True, output.split('\n')
    else:
        return False, []


def get_status_byte_output(cmd):
    """ Run the cmd, return the stdout as a bytes, as well as
    the stat of the cmd (True or False), cmd is a list.
    """
    p       = Popen(cmd, stdout=PIPE)
    output  = p.communicate()[0]
    stat    = p.wait()
    if stat == 0:
        return True, output
    else:
        return False, b''


def reachable(start_commit, end_commit):
    """ Check if start_commit is reachable from the end_commit """
    cmd = 'git merge-base %s %s' % (start_commit, end_commit)
    stat, output = get_status_text_output(cmd)
    if stat:
        base = output[0]
        cmd = 'git rev-parse --verify %s' % start_commit
        stat, output = get_status_text_output(cmd)
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
    cmd = 'git log --pretty=format:"%H" ' + rev_range
    stat, commits = get_status_text_output(cmd)
    return commits


def tree_of_commit(commit):
    """ Return the id of the tree object of the given commit
    """
    cmd = 'git rev-parse %s^{tree}' % commit
    stat, text = get_status_text_output(cmd)
    return text[0]


def files_of_commit(commit):
    """ Return a list of file path that affected by the given commit
    """
    cmd = 'git log -1 --pretty=format: --name-only %s' % commit
    stat, text = get_status_text_output(cmd)
    return text


def object_id_of_file(tree, filename):
    """ Find the object ID of the file in the tree
    """
    cmd = "git cat-file -p %s | awk -F'\\t' '$2 == \"%s\"{gsub(\".* \", \"\", $1); print $1}'" % (
            tree, filename)
    stat, text = get_status_text_output(cmd)
    return text[0] if len(text) > 0 else ""


def collect_object_ids(commit):
    """ Collect IDs of all new objects of a given commit,
    from the commit down to the blob object.
    """
    ids = set()
    ids.add(commit)                     # add the commit itself
    top_tree = tree_of_commit(commit)
    affected_files = files_of_commit(commit)
    for path in affected_files:
        next  = top_tree
        names = path.split(os.sep)
        for name in names:
            ids.add(next)               # the 'next' is the tree in the path
            next = object_id_of_file(next, name)
            if not next: break          # tree will be empty for file deletion
        if next: ids.add(next)          # this is the blob of the file
    ids.add(top_tree)                   # empty commit contains no files, so the
    return ids                          # top_tree not been added yet.


def object_type(id):
    """ Return the object type string.
    """
    cmd = 'git cat-file -t %s' % id
    stat, text = get_status_text_output(cmd)
    return text[0]


def copy_object(id, file):
    """ fetch the content of an object identified by id, attach
    a header, compress it, and store it to a file of path 'file'.
    """
    otype   = object_type(id)
    cmd     = ['git', 'cat-file', otype, id]
    stat, content = get_status_byte_output(cmd)
    header  = '%s %s%s' % (otype, len(content), '\x00')
    store   = header.encode() + content
    z_data  = zlib.compress(store)
    open(file, 'wb').write(z_data)
    return stat


def copy_out_objects(commit, topdir=None):
    """ Copy out objects created by the given commit, and save
    them to files like the structure of .git/objects, that is,
    two chars for directory name, 38 chars for file name.
    """
    topdir = topdir if topdir else commit
    os.mkdir(topdir)
    ids = collect_object_ids(commit)
    for id in ids:
        dir  = os.path.join(topdir, id[:2])
        file = os.path.join(dir, id[2:])
        os.makedirs(dir, exist_ok=True)
        copy_object(id, file)


def tar_to_stdout(path, stdout):
    """ Tar archive the given path, write to stdout
    """
    p = Popen(['tar', '-cf', '-', path], stdout=stdout)
    return p


def encrypt_pipe(stdin, stdout, key):
    """ Encrypt the data from the stdin, write it to stdout
    """
    infd, outfd = os.pipe()
    p = Popen(['gpg', '-c', '--passphrase-fd=%s' % infd, '--cipher-algo=aes'],
                stdin=stdin, stdout=stdout, pass_fds=[infd])
    f = os.fdopen(outfd, 'w')
    f.write(key)
    f.close()
    return p


def pipe_to_object(stdin, stdout):
    """ Read data from stdin and save it to a Git hash-object.
    """
    p = Popen(['git', 'hash-object', '-w', '--stdin'],
                stdin=stdin, stdout=stdout)
    return p


def cleanup(path):
    """ Remove the path, including all files in it if it's a directory.
    """
    getstatusoutput('rm -rf %s' % path)


def encrypt_path(path, key):
    """ Archive the path, encrypt it, and create a new blob for it,
    return the new encrypted blob's ID
    """
    p1 = tar_to_stdout(path=path, stdout=PIPE)
    p2 = encrypt_pipe(stdin=p1.stdout, stdout=PIPE, key=key)
    p3 = pipe_to_object(stdin=p2.stdout, stdout=PIPE)
    id = p3.communicate()[0].decode()
    return id

def encrypt_one_commit(commit, key):
    """ Transform all objects of the given commit to an encrypted format.
        -- Copy out all objects of a commit
        -- Encrypt all files to a new blob
        -- Remove all temporary files and directories
        -- Return the new encrypted blob's ID
    """
    dir = commit
    copy_out_objects(commit, dir)
    id = encrypt_path(dir, key)
    cleanup(dir)
    return id
