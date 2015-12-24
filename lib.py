import os, sys
import hashlib, zlib
import time
from subprocess import Popen, PIPE, getstatusoutput

class ShellCmdErrorException(Exception): pass
class NotReachableException(Exception): pass
class NoPubKeyException(Exception): pass
class NotGitRepoException(Exception): pass

empty_object_id = '0' * 40
shadow_git_dir  = 'shadow'

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
    if not gitdir:
        raise NotGitRepoException
    return gitdir


def get_position_record(branch):
    """ Return a tuple of positions of the branch and its cipher
    counterpart. Of the plain branch, it is the commit which got
    transformed and pushed recently, of the cipher branch, it is
    the commit which synchronized with the remote recently.  If
    the branch had never been pushed, return 40 zeros. The info
    of the cipher branch can be altered when push to a remote, and
    can also be altered when merge remote changes.

    Format of the pushed record file:

        branch-name:plaintext-commit:ciphertext-commit

    """
    filename     = 'location'
    gitdir       = find_git_dir()
    record_path  = os.path.join(gitdir, shadow_git_dir, filename)
    flag         = branch + ':'
    result       = [empty_object_id, empty_object_id]
    try:
        for line in open(record_path):
            if line.startswith(flag):
                result = line.strip().split(':')[1:]
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
        output = output.split('\n') if output else []
        res    = (True, output)
    else:
        res    = (False, [])
    return res


def get_status_byte_output(cmd):
    """ Run the cmd, return the stdout as a bytes, as well as
    the stat of the cmd (True or False), cmd is a list.
    """
    p       = Popen(cmd, stdout=PIPE)
    output  = p.communicate()[0]
    stat    = p.wait()
    res    = (True, output) if stat == 0 else (False, b'')
    return res


def in_proc_out(cmd, in_data):
    """ Run shell command 'cmd', pass 'in_data' to the 'cmd' as
    its standard input, return its standard output. The cmd shall
    be a list, and in_data shall be a bytes.
    """
    p = Popen(cmd, stdin=PIPE, stdout=PIPE)
    p.stdin.write(in_data)
    output = p.communicate()[0]
    stat   = p.wait()
    res    = (True, output) if stat == 0 else (False, b'')
    return res


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
    if start_commit == empty_object_id:
        rev_range = end_commit
    else:
        if not reachable(start_commit, end_commit):
            msg = '%s is not reachable from %s' % (start_commit, end_commit)
            raise NotReachableException(msg)
        else:
            rev_range = '%s..%s' % (start_commit, end_commit)
    cmd = 'git log --pretty=format:"%H" ' + rev_range
    stat, commits = get_status_text_output(cmd)
    return commits[::-1]    # oldest first


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
    os.makedirs(topdir, exist_ok=True)
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
    """ Encrypt the data from the stdin, write it to stdout.
    The key shall be a bytes.
    """
    infd, outfd = os.pipe()
    p = Popen(['gpg', '-q', '-c', '--passphrase-fd=%s' % infd, '--cipher-algo=aes'],
                stdin=stdin, stdout=stdout, pass_fds=[infd])
    f = os.fdopen(outfd, 'wb')
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
    id = p3.communicate()[0].decode().strip()
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


def create_tree(blob_id, file_name, base):
    """ Create a tree object with the provided blob id and file name. Argument
    'base' is the base commit on which we are going to create a new tree object,
    if it is all zero (40 zeros), we will start from empty, if it is not all zero,
    we will base on it and add the blob and file info onto it. Return the new
    tree's object id. When we start from empty, we first backup the possibly
    existing index file and create our own, then restore it backup when finished;
    if we don't start from empty, we checkout to that base commit first, and go
    back to the original position when finished.
    """
    GIT_INDEX_FILE = ".git/index"
    orig_tree_data = None
    orig_pos       = None
    if base == empty_object_id:
        # backup the existing index
        if os.path.exists(GIT_INDEX_FILE):
            orig_tree_data = open(GIT_INDEX_FILE, 'rb').read()
            os.unlink(GIT_INDEX_FILE)
    else:
        # checkout to the base commit, but log the current position first
        orig_pos = current_branch()
        cmd = 'git checkout %s' % base
        stat, output = get_status_text_output(cmd)
        if not stat: raise ShellCmdErrorException('error: ' + cmd)

    cmd = 'git update-index --add --cacheinfo 100644 %s %s' % (blob_id, file_name)
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException('error: ' + cmd)
    cmd = 'git write-tree'
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException('error: ' + cmd)
    tree_id = output[0]

    # restore the index to the state before our work
    if orig_tree_data is not None:
        i = open(GIT_INDEX_FILE, 'wb')
        i.write(orig_tree_data)
        i.close()
    elif orig_pos is not None:
        cmd = 'git checkout -f %s' % orig_pos
        stat, output = get_status_text_output(cmd)
        if not stat: raise ShellCmdErrorException('error: ' + cmd)

    return tree_id

def current_branch():
    """ Return current branch's name
    """
    cmd = 'git branch'
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException('error: ' + cmd)
    pos = [x for x in output if x.startswith('*')][0]
    if 'detached' in pos:
        pos = pos.split()[-1][:-1]
    else:
        pos = pos.split()[-1]
    return pos

def create_commit(tree, parent, message):
    """ Create a commit object with the provided tree, parent, and message.
    If the parent is all zero (40 zeros), we create a commit without a parent.
    Return the id of the commit object.
    """
    cmd = ['git', 'commit-tree', tree]
    if parent != empty_object_id:
        cmd.extend(['-p', parent])
    stat, output = in_proc_out(cmd, message.encode())
    if not stat: raise ShellCmdErrorException('error: ' + ' '.join(cmd))
    return output.decode().strip()


def dense_time_str(second=None):
    """ Return a time string from a second, no separator
    """
    second = second if second else time.time()
    return time.strftime('%Y%m%d%H%M%S', time.localtime(second))


def update_branch(name, commit):
    """ Update the branch to point to the given commit, the
    branch will be automatically created if it does not exist.
    It can also be used to move the branch back in the history,
    when move it back to an not-exists commit (40 zeros), remove
    the branch instead of update.
    """
    if commit == empty_object_id:
        remove_branch(name)
    else:
        cmd = 'git update-ref refs/heads/%s %s' % (name, commit)
        stat, output = get_status_text_output(cmd)
        if not stat: raise ShellCmdErrorException('error: ' + cmd)


def secure_key(key, tag_name):
    """ Encrypt the key and save it to a blob object; create a new tag
    with name 'tag_name' that points to the encrypted key's blob object.
    The key shall be a bytes. Ruturn the blob id of the key's hash object.
    """
    # encrypt the key
    gpg_cmd = ['gpg', '-q', '-e']
    pubkeys = read_pubkeys()
    if not pubkeys:
        raise NoPubKeyException('no public key available')
    for pubkey in pubkeys:
        gpg_cmd.extend(['-r', pubkey])
    git_cmd = ['git', 'hash-object', '-w', '--stdin']
    p1 = Popen(gpg_cmd, stdin=PIPE, stdout=PIPE)
    p2 = Popen(git_cmd, stdin=p1.stdout, stdout=PIPE)
    p1.stdin.write(key)
    p1.stdin.close()
    blob_id = p2.communicate()[0].decode().strip()
    stat    = p2.wait()
    if stat != 0: raise ShellCmdErrorException('error: %s | %s' % (' '.join(gpg_cmd), ' '.join(git_cmd)))

    # create a tag for the cipher key's blob object
    cmd = 'git tag %s %s' % (tag_name, blob_id)
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException('error: ' + cmd)

    return blob_id


def generate_key():
    """ Generate a random key, return a bytes
    """
    size = 128
    key  = open('/dev/urandom', 'rb').read(size)
    return key


def read_pubkeys():
    """ Read the public keys of the cipher data recipients from the
    shadow-git config file, return a list.
    """
    filename = 'pubkeys'
    gitdir   = find_git_dir()
    path     = os.path.join(gitdir, shadow_git_dir, filename)
    result   = []
    try:
        lines  = open(path).readlines()
        result = [x.strip() for x in lines if x != '\n']
    except:
        pass
    return result


def push(remote, branch, tag):
    """ Push the branch and symkey's tag to the remote using
    git-push. If the branch failed, don't push the tag.
    """
    cmd  = 'git push %s %s' % (remote, branch)
    stat = os.system(cmd)
    if stat == 0:
        cmd  = 'git push %s %s' % (remote, tag)
        stat = os.system(cmd)
    return stat == 0


def update_position_record(branch, plain_commit, cipher_commit):
    """ Record the latest pushed cipher-branch and its plaintext
    counterpart. Update if already exists, otherwise create a new.
    """
    filename     = 'location'
    gitdir       = find_git_dir()
    shadow_dir   = os.path.join(gitdir, shadow_git_dir)
    record_path  = os.path.join(shadow_dir, filename)
    data         = []
    if os.path.exists(record_path):
        # update
        f    = open(record_path, 'a+')
        data = f.readlines()
        f.truncate(0)
        flag = branch + ':'
        for line in data:
            if line.startswith(flag):
                data.remove(line)
                break
    else:
        # create a new
        os.makedirs(shadow_dir, exist_ok=True)
        f    = open(record_path, 'w')

    plain_commit  = revision_parse(plain_commit)
    cipher_commit = revision_parse(cipher_commit)
    data.append('%s:%s:%s\n' % (branch, plain_commit, cipher_commit))
    for line in data:
        f.write(line)
    f.close()


def revision_parse(rev):
    """ Use git-rev-parse to parse the rev name
    """
    cmd = 'git rev-parse %s' % rev
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException(cmd)
    id = output[0]
    return id


def remove_tag(tag_name):
    """ Remove the tag of name 'tag_name'
    """
    cmd = 'git tag -d %s' % tag_name
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException('error: ' + cmd)


def remove_branch(branch_name):
    """ Remove the branch of name 'tag_name'
    """
    cmd = 'git branch -D %s' % branch_name
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException('error: ' + cmd)


def prune_objects(ids):
    """ Remove the object files from the Git object directory.
    Because these objects are all new created, they had not gone
    to a pack file yet.
    """
    gitdir       = find_git_dir()
    object_dir   = os.path.join(gitdir, 'objects')
    for id in ids:
        dir  = os.path.join(object_dir, id[:2])
        file = os.path.join(dir, id[2:])
        os.unlink(file)


def fetch(remote, src, dst):
    """ Fetch the branch 'src' from remote to dst with git-fetch
    """
    cmd      = 'git fetch %s %s:%s' % (remote, src, dst)
    stat     = os.system(cmd)
    tag_name = None
    if stat == 0:           # get the symkey
        cmd = 'git rev-parse %s^{tree}' % dst
        stat, output = get_status_text_output(cmd)
        if not stat: raise ShellCmdErrorException(cmd)
        tree_name     = output[0]
        tag_name      = 'symkey-' + tree_name
        tag_local_ref = 'refs/tags/' + tag_name
        cmd  = 'git fetch %s %s:%s' % (remote, tag_name, tag_local_ref)
        stat = os.system(cmd)
    return (stat == 0, tag_name)


def decrypt_key(key_tag):
    """ Decrypt the key pointed by the tag 'key_tag',
    Return the plain-text key, it is a bytes.
    """
    git_cmd = ['git', 'cat-file', 'blob', key_tag]
    gpg_cmd = ['gpg', '-q', '-d']
    p1      = Popen(git_cmd, stdout=PIPE)
    p2      = Popen(gpg_cmd, stdin=p1.stdout, stdout=PIPE)
    key     = p2.communicate()[0]
    stat    = p2.wait()
    if stat != 0: raise ShellCmdErrorException('error: %s | %s' % (' '.join(git_cmd), ' '.join(gpg_cmd)))
    return key


def object_to_pipe(id, otype):
    """ Read the Git object and write it to pipe
    """
    cmd = ['git', 'cat-file', otype, id]
    p = Popen(cmd, stdout=PIPE)
    return p


def decrypt_pipe(stdin, key):
    """ Decrypt the data from pipe and write it to pipe
    """
    infd, outfd = os.pipe()
    cmd = ['gpg', '-q', '-d', '--passphrase-fd=%s' % infd]
    p = Popen(cmd, stdin=stdin, stdout=PIPE, pass_fds=[infd])
    f = os.fdopen(outfd, 'wb')
    f.write(key)
    f.close()
    return p


def untar_from_stdin(stdin, extra_opts=[]):
    """ Extract data from stdin
    """
    cmd = ['tar', '-xf', '-'] + extra_opts
    p = Popen(cmd, stdin=stdin, stdout=PIPE)
    return p


def extract_from_message(commit, keyword):
    """ Return a designated part of data from the commit message, used
    to extract the Blob id, the tip of the branch of a cipher commit.
    """
    cmd = 'git cat-file -p %s' % commit
    stat, output = get_status_text_output(cmd)
    if not stat: raise ShellCmdErrorException(cmd)
    line    = [x for x in output if keyword in x][0]
    target  = line.split()[-1]
    return target


def get_cipher_blob_id(commit):
    """ Return the object id of the cipher blob in a cipher commit
    """
    return extract_from_message(commit, 'Blob:')


def get_tip_inside_cipher(commit):
    """ Return the tip object of the branch inside the cipher commit
    """
    return extract_from_message(commit, 'Top:')


def decrypt_commit(commit, key):
    """ Decrypt the encrypted blob object of the cipher commit
    """
    gitdir     = find_git_dir()
    object_dir = os.path.join(gitdir, 'objects')
    blob_id    = get_cipher_blob_id(commit)
    p1         = object_to_pipe(blob_id, 'blob')
    p2         = decrypt_pipe(p1.stdout, key)
    p3         = untar_from_stdin(p2.stdout, ['-C', object_dir, '--strip-components=1'])
    p3.communicate()
    stat       = p3.wait()
    if stat != 0: raise ShellCmdErrorException('error: decrypt commit')
    return get_tip_inside_cipher(commit)


def merge(branch):
    """ Merge the branch 'branch' into the current branch with git-merge
    """
    cmd      = 'git merge %s' % branch
    stat     = os.system(cmd)
    return stat == 0


def calc_plain_position(old_cur, remote, cur, old_record):
    """ Calculate the commit id on which the next shadow-push will
    find out the change set to push. If the old_record is not an
    empty object id, return it, otherwise, figure out one.
    """
    if old_record != empty_object_id:
        return old_record
    old_cur = revision_parse(old_cur)
    cur     = revision_parse(cur)
    remote  = revision_parse(remote)
    set1 = find_all_commits(old_cur, cur)
    set2 = find_all_commits(remote, cur)

    if len(set1) < len(set2):   # make sure set1 is longer
        set3 = set1
        set1 = set2
        set2 = set3
    common_len = len(set2)
    if common_len == 0:
        diff_set = set1
    else:
        diff_set = set1[:-common_len]
    if len(diff_set) == 0:
        return old_record   # possible?
    else:
        return diff_set[-1]


def shadow_initialized():
    """ Check if the shadow-git environment had been initialized
    """
    gitdir   = find_git_dir()
    dir_name = 'shadow'
    filename = '.initialized'
    path     = os.path.join(gitdir, dir_name, filename)
    return os.path.exists(path)


def is_git():
    """ Return True if it's a git repository
    """
    try:
        find_git_dir()
    except NotGitRepoException as e:
        return False
    return True


def env_ok():
    """ Check if it is a git repository, and shadow-git initialized
    """
    if not is_git():
        print('fatal: Not a git repository', file=sys.stderr)
        return False
    if not shadow_initialized():
        print('fatal: shadow git not initialized', file=sys.stderr)
        return False
    return True


def create_shadow_dir():
    gitdir   = find_git_dir()
    path     = os.path.join(gitdir, shadow_git_dir)
    os.makedirs(path, exist_ok=True)


def add_pubkey():
    """ Add one public key to the key file
    """
    filename = 'pubkeys'
    gitdir   = find_git_dir()
    path     = os.path.join(gitdir, shadow_git_dir, filename)
    name     = None
    email    = None
    while not name: name = input('Your name: ')
    while not email: email = input('Email: ')
    while True:
        keyid = input('Public key [%s]: ' % email)
        if not keyid: keyid = email
        if pubkey_exists(keyid):
            break
        else:
            print("key %s not available"  % keyid, file=sys.stderr)
    data = '{name} <{email}>:{keyid}\n'.format(name=name, email=email, keyid=keyid)
    open(path, 'a').write(data)
    return '%s <%s>' % (name, email)


def pubkey_exists(keyid):
    """ Check if the public key is accessible by gpg command
    """
    cmd = 'gpg --list-keys %s' % keyid
    stat, output = get_status_text_output(cmd)
    return stat


def install_hook():
    """ Install the push hook
    """
    script=r"""#!/bin/sh
remote="$1"
url="$2"
z40=0000000000000000000000000000000000000000
IFS=' '
while read local_ref local_sha remote_ref remote_sha
do
	if [ "$local_sha" = $z40 ]
	then
		# Handle delete
		:
	else
		if [ "$remote_sha" = $z40 ]
		then
			# New branch, examine all commits
			range="$local_sha"
		else
			# Update to existing branch, examine new commits
			range="$remote_sha..$local_sha"
		fi

		# Check for encryption flag
        cipher_commit=$(git rev-list --grep '^CIPHER$' --grep '^Tree' --grep '^Blob' \
                            --grep '^Top' --grep '^Bot' --all-match "$range" | wc -l)
        total_commit=$(git rev-list "$range" | wc -l)
		if [ "$cipher_commit" -ne "$total_commit" ]; then
			echo "some plaintext commits found in $local_ref, not pushing"
			exit 1
		fi
	fi
done

exit 0
"""
    filename = 'pre-push'
    gitdir   = find_git_dir()
    path     = os.path.join(gitdir, 'hooks', filename)
    open(path, 'w').write(script)
    os.system('chmod +x ' + path)


def setup_identity():
    """ Generate a fake identity
    """
    random_data = generate_key()
    sha = hashlib.sha1(random_data).hexdigest()
    name1, name2, email1, email2, email3 = (sha[:7], sha[7:14], sha[14:25], sha[25:37], sha[37:])
    data = '%s %s:%s@%s.%s\n' % (name1, name2, email1, email2, email3)
    filename = 'id'
    gitdir   = find_git_dir()
    path     = os.path.join(gitdir, shadow_git_dir, filename)
    open(path, 'w').write(data)


def read_shadow_id():
    """ Read the shadow identity from shadow config file
    """
    filename = 'id'
    gitdir   = find_git_dir()
    path     = os.path.join(gitdir, shadow_git_dir, filename)
    data     = open(path, 'r').read()
    return data.strip().split(":")


def set_init_mark():
    """ Create the mark file .git/shadow/.initialized
    """
    gitdir   = find_git_dir()
    dir_name = 'shadow'
    filename = '.initialized'
    path     = os.path.join(gitdir, dir_name, filename)
    open(path, 'w')
