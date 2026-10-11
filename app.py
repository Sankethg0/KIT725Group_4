# Teaching package: KIT725-G04-95BA8BE5
"""University course registration console application."""

# ORIGINAL COMMENTS AND CODE PROVENANCE
# Preserve all original comments supplied with this file. Do not remove or alter
# them, including the Teaching package and Reference markers. Add your own
# identification, analysis and patch comments beside the relevant functions.
# When replacing a function, retain the original version as commented code and
# keep only one version active, following the overall patching instructions.
#
# This application combines human-written and AI-generated code. Some parts
# were developed through "vibe coding", using iterative prompts and revisions.
#
# To record the code's provenance, the package includes group-specific reference
# markers, a package identifier and data variations. These distinguish this
# group's version and allow it to be traced back to the original issued package.
# Preserve these identifiers and all original comments when making changes.
#
# Focus your vulnerability analysis on the functions in app.py. Do not spend
# assessment time decoding reference markers or analysing db_setup.py, which
# prepares the database and environment and is outside the assessment scope.

# ASSESSMENT SCOPE
#
# This file contains the application workflow that students must analyse for
# the assignment. It handles user interaction, account actions, enrolments,
# academic records, documents and fee-related operations.
#
# Students should focus their code review, demonstrations, patches and tests
# on app.py. The separate
# db_setup.py file only prepares the SQLite database and supporting environment;
# it is outside the vulnerability-counting scope.
#
# Do not treat this scope note as a list of answers. Students are expected to
# identify the weaknesses by tracing input, decisions, database operations and
# file or process interactions through the code.
import argparse
import getpass
import hashlib
import hmac
import json
import os
from pathlib import Path
import pickle
import sqlite3
import shlex
import subprocess
import sys
import tempfile

from db_setup import initialise, password_record



# Reference: 2EEB6810
def close(lab):
    lab['db'].close()


def require(lab, *roles):
    if lab['user'] is None:
        raise PermissionError('Please log in')
    if roles and lab['user']['role'] not in roles:
        raise PermissionError('Role not permitted')



def matches(password, record):
    (salt, expected) = record.split(':')
    actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 120000).hex()
    return hmac.compare_digest(actual, expected)

# Reference: 43EEC87B
def login(lab, username, password):
    lab['user'] = None
    row = lab['db'].execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if row is None or not matches(password, row['password']):
        raise PermissionError('Invalid credentials')
    lab['user'] = dict(row)
    return {'username': row['username'], 'role': row['role']}

def logout(lab):
    lab['user'] = None
    return 'Logged out'

def register(lab, username, password, email, dob, role):
    if role not in ('student', 'lecturer', 'admin'):
        raise ValueError('Unknown role')
    with lab['db']:
        cursor = lab['db'].execute('INSERT INTO users(username,password,role,email,dob) VALUES(?,?,?,?,?)', (username, password_record(password), role, email, dob))
    return cursor.lastrowid

# Reference: 34B400D5
def directory(lab):
    require(lab)
    return [dict(r) for r in lab['db'].execute('SELECT username,role,email,dob FROM users')]

def legacy_login(lab, username):
    row = lab['db'].execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    if row is None:
        raise ValueError('User not found')
    lab['user'] = dict(row)
    return 'Legacy session started'

def support_login(lab, key):
    if not hmac.compare_digest(key, 'G04-SUPPORT-8N2W-2026'):
        raise PermissionError('Invalid support key')
    lab['user'] = dict(lab['db'].execute("SELECT * FROM users WHERE username='admin'").fetchone())
    return 'Support session started'

def recover(lab, username, dob, new_password):
    row = lab['db'].execute('SELECT id FROM users WHERE username=? AND dob=?', (username, dob)).fetchone()
    if row is None:
        raise PermissionError('Recovery details do not match')
    with lab['db']:
        lab['db'].execute('UPDATE users SET password=? WHERE id=?', (password_record(new_password), row['id']))
    return 'Password reset'

def catalogue(lab, query):
    require(lab)
    rows = lab['db'].execute("SELECT code,title FROM courses WHERE title LIKE '%" + query + "%'").fetchall()
    return [dict(r) for r in rows]

def enrol(lab, code):
    require(lab, 'student')
    lab['db'].execute('BEGIN IMMEDIATE')
    with lab['db']:
        _enrol(lab, code)
    return 'Enrolled'

def _enrol(lab, code):
    course = lab['db'].execute('SELECT * FROM courses WHERE code=?', (code,)).fetchone()
    if course is None or not course['open']:
        raise ValueError('Unit unavailable')
    count = lab['db'].execute('SELECT COUNT(*) FROM enrolments WHERE course=?', (code,)).fetchone()[0]
    if count >= course['capacity']:
        raise ValueError('Unit full')
    lab['db'].execute('INSERT INTO enrolments VALUES(?,?,NULL)', (lab['user']['id'], code))

# Reference: 20F10392
def withdraw(lab, code):
    require(lab, 'student')
    with lab['db']:
        cursor = lab['db'].execute('DELETE FROM enrolments WHERE student=? AND course=?', (lab['user']['id'], code))
    if not cursor.rowcount:
        raise ValueError('Enrolment not found')
    return 'Withdrawn'

def transcript(lab, student):
    require(lab)
    return [dict(r) for r in lab['db'].execute('SELECT course,grade FROM enrolments WHERE student=?', (int(student),))]

def set_grade(lab, student, code, grade):
    require(lab)
    grade = float(grade)
    if not 0 <= grade <= 100:
        raise ValueError('Grade must be 0–100')
    with lab['db']:
        cur = lab['db'].execute('UPDATE enrolments SET grade=? WHERE student=? AND course=?', (grade, int(student), code))
    if not cur.rowcount:
        raise ValueError('Enrolment not found')
    return 'Grade updated'

def set_registration(lab, code, opened):
    with lab['db']:
        cursor = lab['db'].execute('UPDATE courses SET open=? WHERE code=?', (int(opened), code))
    if not cursor.rowcount:
        raise ValueError('Unit not found')
    return 'Registration setting updated'

# Reference: DCDCBD1B
def import_plan(lab, filename):
    require(lab, 'student')
    with open(filename, 'rb') as stream:
        plan = pickle.load(stream)
    if not isinstance(plan, list) or not all((isinstance(c, str) for c in plan)):
        raise ValueError('Expected a list of course codes')
    lab['db'].execute('BEGIN IMMEDIATE')
    with lab['db']:
        for code in plan:
            _enrol(lab, code)
    return 'Study plan imported'

def fee_adjustment(lab, student, amount, reference=''):
    require(lab, 'admin')
    (student_id, value) = (int(student), float(amount))
    lab['db'].execute('BEGIN IMMEDIATE')
    with lab['db']:
        if reference:
            previous = lab['db'].execute('SELECT student,amount FROM adjustments WHERE reference=?', (reference,)).fetchone()
            if previous:
                if previous['student'] != student_id or previous['amount'] != value:
                    raise ValueError('Reference already used for a different adjustment')
                return 'Fee adjustment already recorded'
        lab['db'].execute('INSERT INTO adjustments(student,amount,reference) VALUES(?,?,?)', (student_id, value, reference or None))
    return 'Fee adjustment saved'

def estimate(lab, expression):
    require(lab, 'student')
    credits = lab['db'].execute('SELECT COUNT(*) FROM enrolments WHERE student=?', (lab['user']['id'],)).fetchone()[0] * 12.5
    return eval(expression, {'credits': credits, 'rate': 150})

def read_document(lab, filename):
    require(lab)
    return (lab['documents'] / filename).read_text(encoding='utf-8')

def document_count(lab, pattern):
    require(lab, 'lecturer', 'admin')
    helper = 'import glob,sys; print(len(glob.glob(sys.argv[1])))'
    args = [sys.executable, '-c', helper]
    prefix = subprocess.list2cmdline(args) if os.name == 'nt' else shlex.join(args)
    command = prefix + ' "' + pattern + '"'
    return subprocess.check_output(command, shell=True, cwd=lab['documents'], text=True, encoding='utf-8').strip()

def preview_letters(lab, copies):
    require(lab)
    letters = ['Confirmation %s: %s' % (n, lab['user']['username']) for n in range(int(copies))]
    return {'generated': len(letters), 'first': letters[:1]}

# Reference: 4840EE4E
def set_course_capacity(lab, code, capacity):
    require(lab, 'lecturer', 'admin')
    capacity = int(capacity)
    if not 1 <= capacity <= 200:
        raise ValueError('Capacity must be between 1 and 200')
    lab['db'].execute('BEGIN IMMEDIATE')
    with lab['db']:
        course = lab['db'].execute('SELECT code FROM courses WHERE code=?', (code,)).fetchone()
        if course is None:
            raise ValueError('Unit not found')
        enrolled = lab['db'].execute(
            'SELECT COUNT(*) FROM enrolments WHERE course=?', (code,)
        ).fetchone()[0]
        if capacity < enrolled:
            raise ValueError('Capacity cannot be below current enrolments')
        lab['db'].execute('UPDATE courses SET capacity=? WHERE code=?', (capacity, code))
    return 'Course capacity updated'

def submit_coursework(lab, code, filename):
    require(lab, 'student')
    enrolment = lab['db'].execute(
        'SELECT 1 FROM enrolments WHERE student=? AND course=?',
        (lab['user']['id'], code)
    ).fetchone()
    if enrolment is None:
        raise ValueError('Enrol in this unit before submitting coursework')
    source = Path(filename)
    with source.open('rb') as stream:
        content = stream.read(65537)
    if not content or len(content) > 65536:
        raise ValueError('Submit a non-empty file of at most 64 KiB')
    with lab['db']:
        cursor = lab['db'].execute(
            'INSERT INTO submissions(student,course,filename,content,preview) VALUES(?,?,?,?,?)',
            (lab['user']['id'], code, source.name, content, '')
        )
    return {'submission_id': cursor.lastrowid, 'status': 'Submitted'}

def view_submission(lab, submission):
    require(lab)
    row = lab['db'].execute(
        'SELECT s.id,s.student,s.course,s.filename,s.content,c.lecturer '
        'FROM submissions s JOIN courses c ON c.code=s.course WHERE s.id=?',
        (int(submission),)
    ).fetchone()
    if row is None:
        raise ValueError('Submission not found')
    user = lab['user']
    if not (user['role'] == 'admin' or
            user['role'] == 'student' and user['id'] == row['student'] or
            user['role'] == 'lecturer' and user['id'] == row['lecturer']):
        raise PermissionError('Submission not available to this account')
    with tempfile.TemporaryDirectory(prefix='coursework-') as folder:
        uploaded = Path(folder) / 'submission'
        uploaded.write_bytes(row['content'])
        result = subprocess.run(
            [sys.executable, str(uploaded)], cwd=folder, capture_output=True,
            text=True, encoding='utf-8', errors='replace', timeout=5
        )
    preview = result.stdout if result.returncode == 0 else row['content'].decode('utf-8', errors='replace')
    with lab['db']:
        lab['db'].execute('UPDATE submissions SET preview=? WHERE id=?', (preview, row['id']))
    record = {key: row[key] for key in ('id', 'student', 'course', 'filename')}
    record['preview'] = preview
    return record

ACTIONS = [
 ('Log in',login,['username','password']),
 ('Register account',register,['username','password','email','dob','role']),
 ('Search catalogue',catalogue,['query']),
 ('Enrol in unit',enrol,['code']),
 ('Withdraw from unit',withdraw,['code']),
 ('View transcript',transcript,['student']),
 ('Record grade',set_grade,['student','code','grade']),
 ('Campus directory',directory,[]),
 ('Open/close registration',set_registration,['code','opened']),
 ('Legacy login',legacy_login,['username']),
 ('Support login',support_login,['key']),
 ('Recover account',recover,['username','dob','new_password']),
 ('Record fee adjustment',fee_adjustment,['student','amount','reference']),
 ('Read university document',read_document,['filename']),
 ('Import study plan',import_plan,['filename']),
 ('Estimate fees',estimate,['expression']),
 ('Count documents',document_count,['pattern']),
 ('Preview confirmation letters',preview_letters,['copies']),
 ('Log out',logout,[]),
 ('Submit coursework',submit_coursework,['code','filename']),
 ('View submission',view_submission,['submission']),
 ('Set course capacity',set_course_capacity,['code','capacity']),
]


# WORKED EXAMPLE ONLY — excluded from the assessed weaknesses.
# CWE IDENTIFICATION
# CWE ID and title: CWE-549 — Missing Password Field Masking.
# This CWE is outside the assignment's permitted 2025 Top 25 and On the Cusp lists.
# Student name: [full name]
# Student ID: [student number]
# Identified by: [student name and student ID]
# Date and time: [student records the date and time of their demonstration]
#
# PRE-PATCH ANALYSIS
# Location: read_password(), called by the login workflow below.
# Function signature: read_password()
# Other weaknesses in this function: none identified for this worked example.
# Trigger: enter a synthetic password at the interactive terminal prompt.
# Root cause: input() echoes the password characters while they are typed.
# Security impact: someone viewing the terminal or a screen recording can read it.
# Evidence: the typed synthetic password is visible before the prompt is submitted.
# Affected functionality: interactive login password entry.
#
# PATCH PLAN
# Intended change: use a password-reading method that suppresses terminal echo.
# Preserved behaviour: valid credentials still log in and invalid credentials fail.
def read_password():
    return input("Password: ")


# POST-PATCH ANALYSIS — worked example only.
# CWE addressed: CWE-549 — Missing Password Field Masking.
# Patched by: [student name and student ID]
# Replacement signature: read_password() — must match the original signature.
# Other weaknesses patched in this replacement: none identified for this worked example.
# Date and time: [student records the date and time of the patched test]
# Change made: replace the active function above with the commented function below.
# Function-level rule: if the original function contains multiple weaknesses,
# the replacement must patch all of them, not only the CWE being documented.
# Why it works: getpass.getpass() normally suppresses terminal echo during entry.
# Verification: type a synthetic password and confirm that its characters are hidden.
# Functionality preserved: a correct login succeeds and an incorrect login is rejected.
# Limitation: this does not protect stored passwords or prevent keyboard monitoring.
# Evidence: record the before/after terminal result and the login test output.
# Use VS Code's integrated terminal; unsupported consoles may warn and echo input.
# Keep exactly one read_password() definition active.
#
# def read_password():
#     return getpass.getpass("Password: ")


def main():
    parser = argparse.ArgumentParser(description='KIT725 Group 4 University Registration — offline teaching lab')
    parser.add_argument('--data-dir',default='lab_data',help='SQLite and document directory')
    parser.add_argument('--init-only',action='store_true',help='Create data and exit')
    args = parser.parse_args()
    try:
        lab = initialise(args.data_dir)
    except (OSError, sqlite3.Error, ValueError) as error:
        print('Cannot open application data:', error)
        return
    try:
        if args.init_only:
            print('Database ready:',lab['root']/'university.sqlite3')
            return
        print('University Registration | KIT725-G04-95BA8BE5 | Synthetic data only')
        while True:
            print('\nSession:',lab['user']['username']+' ('+lab['user']['role']+')' if lab['user'] else 'guest')
            for n,(label,_,_) in enumerate(ACTIONS,1):
                print('%2d. %s'%(n,label))
            print(' 0. Exit')
            try:
                try:
                    choice = int(input('Choose: '))
                except EOFError:
                    break
                if choice == 0:
                    break
                if not 1 <= choice <= len(ACTIONS):
                    raise ValueError('Choose a listed number')
                _,method,fields = ACTIONS[choice-1]
                try:
                    values = []
                    for name in fields:
                        if method is login and name == 'password':
                            values.append(read_password())
                        elif name in ('password', 'new_password', 'key'):
                            values.append(getpass.getpass(name + ': '))
                        else:
                            values.append(input(name + ': '))
                except EOFError:
                    break
                if method in (import_plan, document_count, preview_letters, submit_coursework):
                    print('Processing ' + ACTIONS[choice-1][0].lower() + '...')
                result = method(lab, *values)
                if isinstance(result, list) and not result:
                    print('No records found. Check your selection or try another search.')
                else:
                    print(json.dumps(result,indent=2) if isinstance(result,(dict,list)) else result)
            except KeyboardInterrupt:
                print('\nExiting')
                break
            except PermissionError as error:
                print('Access denied:', error)
            except sqlite3.IntegrityError:
                print('Record conflicts with existing data or refers to a missing account/unit.')
            except sqlite3.OperationalError as error:
                print('Database operation unavailable. Check your input or retry later:', error)
            except (ValueError, SyntaxError, ArithmeticError, NameError, TypeError) as error:
                print('Check the supplied values:', error)
            except (OSError, UnicodeError) as error:
                print('File or process unavailable. Check the path and permissions:', error)
            except (pickle.UnpicklingError, EOFError):
                print('The study plan could not be read. Select a valid plan file.')
            except subprocess.SubprocessError as error:
                print('Document operation failed. Check the pattern and retry:', error)
    finally:
        close(lab)



if __name__ == '__main__':
    main()
