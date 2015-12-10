import os
import subprocess
import hashlib, zlib

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
    stat, output = subprocess.getstatusoutput(cmd)
    if stat == 0:
        return True, output.split('\n')
    else:
        return False, []


def get_status_byte_output(cmd):
    """ Run the cmd, return the stdout as a bytes, as well as
    the stat of the cmd (True or False), cmd is a list.
    """
    p       = subprocess.Popen(cmd, stdout=subprocess.PIPE)
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
    cmd = 'git log --pretty=format:"%h" ' + rev_range
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


def encrypt_one_commit(commit, key):
    """ Transform all objects of the given commit to an encrypted format.
        -- Collect object IDs,
        -- Copy out objects and save them to files like the
           structure of .git/objects, that is, two chars for
           directory name, 38 chars for file name.
        -- Archive, encrypt, and create a new blob in a pipe
        -- Remove all temporary files and directories
        -- Return the new encrypted blob's ID
    """
    ids = collect_object_ids(commit)

    # copy out all objects and save them to files
    os.mkdir(commit)
    for id in ids:
        dir  = os.path.join(commit, id[:2])
        file = os.path.join(dir, id[2:])
        os.mkdir(dir)
        os.makedirs(dir, exist_ok=True)
        copy_object(id, file)

    # archive, encrypt, save into a new blob
    from subprocess import Popen, PIPE, getstatusoutput
    infd, outfd = os.pipe()
    p1 = Popen(['tar', '-cf', '-', commit], stdout=PIPE)
    p2 = Popen(['gpg', '-c', '--passphrase-fd=%s' % infd, '--cipher-algo=aes'],
                stdin=p1.stdout, stdout=PIPE, pass_fds=[infd])
    f = os.fdopen(outfd, 'w')
    f.write(key)
    f.close()
    p3 = Popen(['git', 'hash-object', '-w', '--stdin'],
                stdin=p2.stdout, stdout=PIPE)
    new_blob_id = p3.communicate()[0].decode()

    # clean
    getstatusoutput('rm -rf %s' % commit)

    return new_blob_id
