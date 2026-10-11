# Teaching package: KIT725-G04-95BA8BE5
"""Create and open the local university dataset."""
import hashlib
import os
from pathlib import Path
import sqlite3


def password_record(password):
    salt = os.urandom(16).hex()
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 120000).hex()
    return salt + ':' + digest


def create_document(path, contents):
    if path.is_symlink():
        raise ValueError('Sample documents must be regular files')
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not path.is_file():
            raise ValueError('Sample document path is not a file')
        return
    with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
        stream.write(contents)


def initialise(directory):
    root = Path(directory).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    documents = root / 'documents'
    if documents.is_symlink():
        raise ValueError('Documents directory must not be a symbolic link')
    documents.mkdir(exist_ok=True, mode=0o700)
    database_path = root / 'university.sqlite3'
    if database_path.is_symlink():
        raise ValueError('Database must not be a symbolic link')
    try:
        descriptor = os.open(database_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not database_path.is_file():
            raise ValueError('Database path is not a file')
    else:
        os.close(descriptor)

    db = sqlite3.connect(database_path)
    db.row_factory = sqlite3.Row
    try:
        db.execute('PRAGMA foreign_keys=ON')
        db.execute('BEGIN IMMEDIATE')
        with db:
            db.execute('CREATE TABLE IF NOT EXISTS package_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute('INSERT OR IGNORE INTO package_metadata VALUES(?,?)', ('variant', 'KIT725-G04-95BA8BE5'))
            db.execute("""CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL, role TEXT NOT NULL,
                email TEXT NOT NULL, dob TEXT NOT NULL)""")
            db.execute("""CREATE TABLE IF NOT EXISTS courses(
                code TEXT PRIMARY KEY, title TEXT NOT NULL,
                lecturer INTEGER REFERENCES users(id), capacity INTEGER NOT NULL,
                open INTEGER NOT NULL DEFAULT 1)""")
            db.execute("""CREATE TABLE IF NOT EXISTS enrolments(
                student INTEGER REFERENCES users(id), course TEXT REFERENCES courses(code),
                grade REAL, PRIMARY KEY(student,course))""")
            db.execute("""CREATE TABLE IF NOT EXISTS adjustments(
                id INTEGER PRIMARY KEY, student INTEGER REFERENCES users(id),
                amount REAL, reference TEXT)""")
            db.execute("""CREATE TABLE IF NOT EXISTS submissions(
                id INTEGER PRIMARY KEY, student INTEGER NOT NULL REFERENCES users(id),
                course TEXT NOT NULL REFERENCES courses(code), filename TEXT NOT NULL,
                content BLOB NOT NULL, preview TEXT NOT NULL)""")
            columns = {row['name'] for row in db.execute('PRAGMA table_info(adjustments)')}
            if 'reference' not in columns:
                db.execute('ALTER TABLE adjustments ADD COLUMN reference TEXT')
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS adjustment_reference ON adjustments(reference)')
            if not db.execute('SELECT 1 FROM users').fetchone():
                accounts = [
                    (1, 'g04_robin', 'student', '2001-07-23'),
                    (2, 'g04_ellis', 'student', '2002-04-12'),
                    (3, 'g04_devon', 'lecturer', '1980-03-03'),
                    (4, 'admin', 'admin', '1970-04-04'),
                    (5, 'g04_rowan', 'lecturer', '1985-05-05'),
                ]
                for user_id, name, role, dob in accounts:
                    db.execute(
                        'INSERT INTO users(id,username,password,role,email,dob) VALUES(?,?,?,?,?,?)',
                        (user_id, name, password_record(name + '-lab-pass'),
                         role, name + '@example.invalid', dob),
                    )
                db.executemany('INSERT INTO courses VALUES(?,?,?,?,?)', [
                    ('G04-C725', 'Cybersecurity', 3, 30, 1),
                    ('G04-C101', 'Programming', 5, 25, 1),
                ])
                db.executemany('INSERT INTO enrolments VALUES(?,?,?)', [
                    (1, 'G04-C725', 72), (2, 'G04-C725', 85),
                ])
        create_document(documents / 'g04-handbook.txt',
                        'University handbook: enrol in open units; contact your lecturer for results.\n')
        create_document(root / 'g04-coursework.txt',
                        'Coursework notes for G04-C725.\n')
        create_document(root / 'g04-registrar-notes.txt',
                        'SYNTHETIC CONFIDENTIAL: review student 2 scholarship.\n')
    except BaseException:
        db.close()
        raise
    return {'root': root, 'documents': documents, 'db': db, 'user': None}
