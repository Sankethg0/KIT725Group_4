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

from datetime import date
from decimal import Decimal, InvalidOperation
import re
import stat
import time
import warnings

# Limits for the local console application.
MAX_FILE_BYTES = 65536
MAX_PLAN_COURSES = 200
MAX_PREVIEW_COPIES = 1000
MAX_SUBMISSIONS = 100
MAX_FEE_AMOUNT = Decimal('1000000')

def _check_text(value, label, maximum, allow_empty=False):
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError('%s must be text of at most %s characters' % (label, maximum))
    if not allow_empty and not value.strip():
        raise ValueError('%s is required' % label)
    return value

def _read_integer(value, label, minimum, maximum):
    if isinstance(value, bool):
        raise ValueError('%s must be an integer' % label)
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r'-?[0-9]{1,19}', value.strip()):
        number = int(value)
    else:
        raise ValueError('%s must be an integer' % label)
    if not minimum <= number <= maximum:
        raise ValueError('%s must be between %s and %s' % (label, minimum, maximum))
    return number

def _current_user(lab, *roles):
    require(lab)
    row = lab['db'].execute(
        'SELECT * FROM users WHERE id=? AND username=?',
        (lab['user']['id'], lab['user']['username'])
    ).fetchone()
    if row is None:
        lab['user'] = None
        raise PermissionError('Please log in again')
    lab['user'] = dict(row)
    if roles and row['role'] not in roles:
        raise PermissionError('Role not permitted')
    return lab['user']

def _check_password(password):
    _check_text(password, 'Password', 1024)
    if len(password) < 12:
        raise ValueError('Use a password of at least 12 characters')
    return password

def _read_password_safely(prompt):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except (EOFError, getpass.GetPassWarning) as error:
        raise PermissionError('Use an interactive terminal for password verification') from error

def _verify_password(lab, username, password):
    _check_text(username, 'Username', 64)
    _check_text(password, 'Password', 1024, allow_empty=True)
    now = time.monotonic()
    attempts = lab.setdefault('_patch_credential_failures', {})
    for name, entry in list(attempts.items()):
        if now - entry['started'] >= 60:
            del attempts[name]
    entry = attempts.get(username)
    if entry is not None and entry['count'] >= 5:
        raise PermissionError('Too many failed attempts; retry after one minute')
    if entry is None and len(attempts) >= 128:
        raise PermissionError('Too many failed attempts; retry after one minute')
    row = lab['db'].execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    valid = False
    if row is not None:
        try:
            valid = matches(password, row['password'])
        except (TypeError, ValueError):
            valid = False
    if not valid:
        entry = attempts.setdefault(username, {'count': 0, 'started': now})
        entry['count'] += 1
        raise PermissionError('Invalid credentials')
    attempts.pop(username, None)
    return dict(row)

def _read_small_file(filename, extensions):
    source = Path(filename)
    if source.suffix.lower() not in extensions:
        raise ValueError('Use one of these file extensions: ' + ', '.join(extensions))
    if source.is_symlink():
        raise ValueError('Select a regular file, not a symbolic link')
    flags = os.O_RDONLY | getattr(os, 'O_NONBLOCK', 0) | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0)
    descriptor = os.open(source, flags)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Select a regular file')
        content = stream.read(MAX_FILE_BYTES + 1)
    if not content or len(content) > MAX_FILE_BYTES:
        raise ValueError('Submit a non-empty file of at most 64 KiB')
    return source, content

def _coursework_text(filename, content):
    _check_text(filename, 'Filename', 255)
    if Path(filename).suffix.lower() not in ('.txt', '.md'):
        raise ValueError('Coursework must be a .txt or .md file')
    if not isinstance(content, bytes) or not content or len(content) > MAX_FILE_BYTES:
        raise ValueError('Submit a non-empty file of at most 64 KiB')
    try:
        text = content.decode('utf-8')
    except UnicodeError as error:
        raise ValueError('Coursework must contain valid UTF-8 text') from error
    if '\x00' in text:
        raise ValueError('Coursework must contain text without NUL bytes')
    return text




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

# CWE IDENTIFICATION
# CWE ID and title: CWE-266 - Incorrect Privilege Assignment
# Student name: Jayasinghe Gunasekara, Sasanka Sanketh
# Student ID: 759596
# Date and time: 15 October 2026, 19:41 AEDT
#
# PRE-PATCH ANALYSIS
# Location: register in app.py
# Function signature: register(lab, username, password, email, dob, role)
# Other weaknesses in this function: CWE-862 (privileged role creation), CWE-20
#   (registration fields)
# Trigger: A guest or student requests role=admin or role=lecturer.
# Root cause: Signup accepted the role chosen by the caller without checking their
#   authority.
# Security impact: An untrusted account gains administrative or teaching privileges.
# Evidence: Guest-created administrator login succeeded in the baseline; the patched request
#   is denied.
# Affected functionality: A guest can register as a student; an administrator can create
#   staff accounts.
#
# PATCH PLAN
# Intended change: Keep student signup open, but require an administrator for lecturer or
#   admin accounts.
# Preserved behaviour: A guest can register as a student; an administrator can create staff
#   accounts.
#
# Original function kept for the before-and-after comparison
# def register(lab, username, password, email, dob, role):
#     if role not in ('student', 'lecturer', 'admin'):
#         raise ValueError('Unknown role')
#     with lab['db']:
#         cursor = lab['db'].execute('INSERT INTO users(username,password,role,email,dob) VALUES(?,?,?,?,?)', (username, password_record(password), role, email, dob))
#     return cursor.lastrowid
#
# POST-PATCH ANALYSIS
# CWE addressed: CWE-266 - Incorrect Privilege Assignment
# Replacement signature: register(lab, username, password, email, dob, role)
# Other weaknesses patched in this replacement: CWE-862 (privileged role creation), CWE-20
#   (registration fields)
# Date and time: 15 October 2026, 19:41 AEDT
# Change made: Keep student signup open, but require an administrator for lecturer or admin
#   accounts.
# Why it works: The permission check runs before the privileged role is inserted.
# Verification: tests/test_security.py::test_register_role_boundary and video_demo.py 266
# Functionality preserved: A guest can register as a student; an administrator can create
#   staff accounts.
# Limitation: Existing privileged accounts require an administrator review; the offline
#   database is trusted.
# Evidence: Assistant-run results in evidence/before_after.json; repeat locally before
#   submission.
def register(lab, username, password, email, dob, role):
    if role not in ('student', 'lecturer', 'admin'):
        raise ValueError('Unknown role')
    if role != 'student':
        _current_user(lab, 'admin')
    _check_text(username, 'Username', 64)
    if not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{2,63}', username):
        raise ValueError('Use a username of 3-64 letters, numbers, underscores, dots or hyphens')
    _check_password(password)
    _check_text(email, 'Email', 254)
    if not re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', email):
        raise ValueError('Enter a valid email address')
    _check_text(dob, 'Date of birth', 10)
    if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', dob):
        raise ValueError('Use YYYY-MM-DD for the date of birth')
    if date.fromisoformat(dob) > date.today():
        raise ValueError('Date of birth cannot be in the future')
    with lab['db']:
        cursor = lab['db'].execute(
            'INSERT INTO users(username,password,role,email,dob) VALUES(?,?,?,?,?)',
            (username, password_record(password), role, email, dob)
        )
    return cursor.lastrowid

# Reference: 34B400D5
# Reference: 34B400D5
# CWE IDENTIFICATION
# CWE ID and title: CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
# Student name: Rabiya Begum
# Student ID: 750636
# Identified by: Rabiya Begum, 750636
# Date and time: 11 October 2026, 23:05, local time

# PRE-PATCH ANALYSIS
# Location: directory(), whole function
# Function signature: directory(lab)
# Other weaknesses in this function: none
# Trigger: log in as any account and choose menu option 8
# Root cause: the query returns every user's date of birth and email to any
#   logged-in account, and the function only calls require(lab) to confirm a login.
# Security impact: date of birth is personal data, and the recover() function uses
#   it as the account recovery secret, so exposing it helps account takeover.
# Evidence: before_directory.txt — student and lecturer sessions received
#   the date of birth of all users.
# Affected functionality: campus directory
#
# PATCH PLAN
# Intended change: return the date of birth only to administrators.
# Preserved behaviour: every logged-in user can still list username, role and
#   email, and guests are still refused.
#
# ORIGINAL FUNCTION (kept as commented code, not active):
# def directory(lab):
#     require(lab)
#     return [dict(r) for r in lab['db'].execute('SELECT username,role,email,dob FROM users')]

# POST-PATCH ANALYSIS
# CWE addressed: CWE-200 — Exposure of Sensitive Information to an Unauthorized Actor
# Patched by: Rabiya Begum, 750636
# Replacement signature: directory(lab)
# Other weaknesses patched in this replacement: none
# Date and time: 11 October 2026, 23:15, local time
# Change made: the query is chosen by the logged-in user's role, and only the
#   admin query selects the dob column.
# Why it works: the sensitive column is never read from the database for
#   non-admin roles, so it cannot leak through the returned records.
# Verification: In after_directory.txt (23:15), the student and lecturer sessions
#   now return only username, role and email for each user, with no dob field,
#   where before the patch (23:05) every session received each user's date of
#   birth. The admin session still receives dob, and the guest is still refused
#   with "Please log in".
# Functionality preserved: The directory still lists all five users for every
#   logged-in role, so the feature works as before, and the admin keeps full
#   access to the records.
# Limitation: Email addresses are still visible to every logged-in user, and
#   limiting dob to administrators is a design choice. The administrator account
#   can still see everyone's date of birth.
# Evidence: before_directory.txt vs after_directory.txt
def directory(lab):
    require(lab)
    if lab['user']['role'] == 'admin':
        query = 'SELECT username,role,email,dob FROM users'
    else:
        query = 'SELECT username,role,email FROM users'
    return [dict(r) for r in lab['db'].execute(query)]

# CWE IDENTIFICATION
# CWE ID and title: CWE-288 - Authentication Bypass Using an Alternate Path or Channel
# Student name: Jayasinghe Gunasekara, Sasanka Sanketh
# Student ID: 759596
# Date and time: 15 October 2026, 19:41 AEDT
#
# PRE-PATCH ANALYSIS
# Location: legacy_login in app.py
# Function signature: legacy_login(lab, username)
# Other weaknesses in this function: CWE-770 (bounded failed-verification state and
#   attempts)
# Trigger: A guest supplies an existing username through the legacy menu.
# Root cause: The legacy route started a session using only a username.
# Security impact: A guest can impersonate an administrator or another user.
# Evidence: Baseline legacy_login(admin) created an administrator session; a wrong password
#   now fails.
# Affected functionality: The legacy menu still logs in a user who supplies the correct
#   password.
#
# PATCH PLAN
# Intended change: Clear the old session and verify the account password before starting
#   another one.
# Preserved behaviour: The legacy menu still logs in a user who supplies the correct
#   password.
#
# Original function kept for the before-and-after comparison
# def legacy_login(lab, username):
#     row = lab['db'].execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
#     if row is None:
#         raise ValueError('User not found')
#     lab['user'] = dict(row)
#     return 'Legacy session started'
#
# POST-PATCH ANALYSIS
# CWE addressed: CWE-288 - Authentication Bypass Using an Alternate Path or Channel
# Replacement signature: legacy_login(lab, username)
# Other weaknesses patched in this replacement: CWE-770 (bounded failed-verification state
#   and attempts)
# Date and time: 15 October 2026, 19:41 AEDT
# Change made: Clear the old session and verify the account password before starting another
#   one.
# Why it works: Knowing a username no longer proves that the caller owns the account.
# Verification: tests/test_security.py::test_legacy_authentication and video_demo.py 288
# Functionality preserved: The legacy menu still logs in a user who supplies the correct
#   password.
# Limitation: The new hidden password prompt requires an interactive terminal; its throttle
#   is process-local.
# Evidence: Assistant-run results in evidence/before_after.json; repeat locally before
#   submission.
def legacy_login(lab, username):
    lab['user'] = None
    password = _read_password_safely('Legacy account password: ')
    lab['user'] = _verify_password(lab, username, password)
    return 'Legacy session started'

# CWE IDENTIFICATION
# CWE ID and title: CWE-798 - Use of Hard-coded Credentials
# Student name: Jayasinghe Gunasekara, Sasanka Sanketh
# Student ID: 759596
# Date and time: 15 October 2026, 19:41 AEDT
#
# PRE-PATCH ANALYSIS
# Location: support_login in app.py
# Function signature: support_login(lab, key)
# Other weaknesses in this function: CWE-770 (bounded failed-verification state and
#   attempts)
# Trigger: A guest uses the support secret embedded in the original source.
# Root cause: A support key written in the source granted an administrator session.
# Security impact: Anyone who knows the issued support key can obtain administrator
#   privileges.
# Evidence: The issued key authenticated before the patch; it is rejected after the patch.
# Affected functionality: Support login still works with the current administrator password.
#
# PATCH PLAN
# Intended change: Use the current administrator password instead of the fixed support key.
# Preserved behaviour: Support login still works with the current administrator password.
#
# Original function kept for the before-and-after comparison
# def support_login(lab, key):
#     if not hmac.compare_digest(key, 'G04-SUPPORT-8N2W-2026'):
#         raise PermissionError('Invalid support key')
#     lab['user'] = dict(lab['db'].execute("SELECT * FROM users WHERE username='admin'").fetchone())
#     return 'Support session started'
#
# POST-PATCH ANALYSIS
# CWE addressed: CWE-798 - Use of Hard-coded Credentials
# Replacement signature: support_login(lab, key)
# Other weaknesses patched in this replacement: CWE-770 (bounded failed-verification state
#   and attempts)
# Date and time: 15 October 2026, 19:41 AEDT
# Change made: Use the current administrator password instead of the fixed support key.
# Why it works: The old source literal is rejected; the stored password hash must match.
# Verification: tests/test_security.py::test_support_authentication and video_demo.py 798
# Functionality preserved: Support login still works with the current administrator
#   password.
# Limitation: The original secret remains in inactive source comments as required; passwords
#   must be rotated by the operator.
# Evidence: Assistant-run results in evidence/before_after.json; repeat locally before
#   submission.
def support_login(lab, key):
    lab['user'] = None
    user = _verify_password(lab, 'admin', key)
    if user['role'] != 'admin':
        raise PermissionError('Administrator account required')
    lab['user'] = user
    return 'Support session started'

# CWE IDENTIFICATION
# CWE ID and title: CWE-287 - Improper Authentication
# Student name: Jayasinghe Gunasekara, Sasanka Sanketh
# Student ID: 759596
# Date and time: 15 October 2026, 19:41 AEDT
#
# PRE-PATCH ANALYSIS
# Location: recover in app.py
# Function signature: recover(lab, username, dob, new_password)
# Other weaknesses in this function: CWE-862 (cross-account reset authority), CWE-770
#   (bounded verification attempts)
# Trigger: A caller knows a target username and date of birth.
# Root cause: A matching date of birth allowed a password reset without proof of identity.
# Security impact: A caller can replace another user password without a genuine identity
#   check.
# Evidence: DOB-only reset succeeded before; the same details plus an incorrect verification
#   password now fail.
# Affected functionality: Verified password changes and administrator-assisted resets still
#   work.
#
# PATCH PLAN
# Intended change: Verify the current account password, or reverify an administrator
#   resetting another account.
# Preserved behaviour: Verified password changes and administrator-assisted resets still
#   work.
#
# Original function kept for the before-and-after comparison
# def recover(lab, username, dob, new_password):
#     row = lab['db'].execute('SELECT id FROM users WHERE username=? AND dob=?', (username, dob)).fetchone()
#     if row is None:
#         raise PermissionError('Recovery details do not match')
#     with lab['db']:
#         lab['db'].execute('UPDATE users SET password=? WHERE id=?', (password_record(new_password), row['id']))
#     return 'Password reset'
#
# POST-PATCH ANALYSIS
# CWE addressed: CWE-287 - Improper Authentication
# Replacement signature: recover(lab, username, dob, new_password)
# Other weaknesses patched in this replacement: CWE-862 (cross-account reset authority),
#   CWE-770 (bounded verification attempts)
# Date and time: 15 October 2026, 19:41 AEDT
# Change made: Verify the current account password, or reverify an administrator resetting
#   another account.
# Why it works: Personal details alone cannot authorize the password update.
# Verification: tests/test_security.py::test_recovery_identity_proof and video_demo.py 287
# Functionality preserved: Verified password changes and administrator-assisted resets still
#   work.
# Limitation: A forgotten password requires administrator assistance; no email/token
#   recovery or cross-process session revocation is provided.
# Evidence: Assistant-run results in evidence/before_after.json; repeat locally before
#   submission.
def recover(lab, username, dob, new_password):
    _check_text(username, 'Username', 64)
    _check_text(dob, 'Date of birth', 10)
    _check_password(new_password)
    actor = _current_user(lab) if lab['user'] is not None else None
    if actor is not None and actor['username'] != username:
        if actor['role'] != 'admin':
            raise PermissionError('Only an administrator can reset another account')
        verifier = _verify_password(lab, actor['username'], _read_password_safely('Administrator password: '))
        administrative = True
    else:
        verifier = _verify_password(lab, username, _read_password_safely('Current account password: '))
        administrative = False
    target = lab['db'].execute(
        'SELECT id FROM users WHERE username=? AND dob=?', (username, dob)
    ).fetchone()
    if target is None:
        raise PermissionError('Recovery details do not match')
    record = password_record(new_password)
    lab['db'].execute('BEGIN IMMEDIATE')
    with lab['db']:
        current = lab['db'].execute('SELECT password,role FROM users WHERE id=?', (verifier['id'],)).fetchone()
        if current is None or current['password'] != verifier['password'] or administrative and current['role'] != 'admin':
            raise PermissionError('Please verify your credentials again')
        lab['db'].execute('UPDATE users SET password=? WHERE id=?', (record, target['id']))
    if lab['user'] is not None and lab['user']['id'] == target['id']:
        lab['user']['password'] = record
    return 'Password reset'

"""python
# CWE IDENTIFICATION
# CWE ID and title: CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# Student name: Hrizu Sharma
# Student ID: 767643
# Identified by: Hrizu Sharma, 767643
# Date and time: 12 October 2026, 18:17, local time
#
# PRE-PATCH ANALYSIS
# Location: app.catalogue function
# Function signature: catalogue(lab, query)
# Other weaknesses in this function: none identified
# Trigger: When user enters SQL injection to input string for query
# Root cause: SQL query is constructed using string concatenation
# Security impact: Attacker is able to inject UNION queries and extract privileged information
# Evidence: Injection search returned list of all accounts instead of course titles
# Affected functionality: course search feature

# PATCH PLAN
# Intended change: use parameterised SQL for query before construction
# Preserved behaviour: Relevant query parameters is accepted by database to produce results
"""
# def catalogue(lab, query):
#     require(lab)
#     rows = lab['db'].execute("SELECT code,title FROM courses WHERE title LIKE '%" + query + "%'").fetchall()
#     return [dict(r) for r in rows]

""" python
# POST-PATCH ANALYSIS
# CWE addressed: CWE-89: Improper Neutralization of Special Elements used in an SQL Command
# Patched by: Hrizu Sharma, 767643
# Replacement signature: catalogue(lab, query)
# Other weaknesses patched in this replacement: none identified
# Date and time: 14 October 2026,  19:56, local time
# Change made: String concatenated SQL was replaced  with a parameterised query and wildcards were also added for preserving original substring.
# Why it works: Parameter binding ensures the input is treated as plain text and results in safe construction of the LIKE pattern.
# Verification: A test with normal and invalid SQL injection input will only return data for normal query.
# Functionality preserved: Relevant query parameters is accepted by database to produce results
# Limitation: This patch does not help if user enters SQL wildcards % or _ in input, the empty query still returns output from database
# Evidence: Before-invalid search: [{'code': 'admin', 'title': 'admin'}, {'code': 'g04_devon', 'title': 'lecturer'}, {'code': 'g04_ellis', 'title': 'student'}, {'code': 'g04_robin', 'title': 'student'}, {'code': 'g04_rowan', 'title': 'lecturer'}]
# Evidence: After-invalid search: [] 
""" 
def catalogue(lab, query):
    require(lab)
    pattern = f"%{query}%"
    rows = lab['db'].execute("SELECT code, title FROM courses WHERE title LIKE ?", (pattern,)).fetchall()
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

# CWE IDENTIFICATION
# CWE ID and title: CWE-639 — Authorization Bypass Through User-Controlled Key
# Student name: Rabiya Begum
# Student ID: 750636
# Identified by: Rabiya Begum, 750636
# Date and time: 11 October 2026, 22:37, local time
#
# PRE-PATCH ANALYSIS
# Location: transcript(), whole function
# Function signature: transcript(lab, student)
# Other weaknesses in this function: CWE-862 / CWE-863 (no ownership or
#   assigned-unit check)
# Trigger: log in as a student and request another student's ID with menu option 6
# Root cause: the function only calls require(lab) to confirm a login, and then
#   queries enrolments with the student ID supplied by the caller.
# Security impact: any logged-in user can read any student's grades by changing
#   the ID, exposing confidential academic records.
# Evidence: before_transcript.txt — student Robin received Ellis's grade (85.0).
# Affected functionality: viewing a transcript
#
# PATCH PLAN
# Intended change: students see only their own record, lecturers see only grades
#   for units they teach, and admins see any student.
# Preserved behaviour: a student still sees their own transcript, and the
#   assigned lecturer and admin still see results.
#
# ORIGINAL FUNCTION (kept as commented code, not active):
# def transcript(lab, student):
#     require(lab)
#     return [dict(r) for r in lab['db'].execute('SELECT course,grade FROM enrolments WHERE student=?', (int(student),))]

# POST-PATCH ANALYSIS
# CWE addressed: CWE-639 — Authorization Bypass Through User-Controlled Key
# Patched by: Rabiya Begum, 750636
# Replacement signature: transcript(lab, student)
# Other weaknesses patched in this replacement: CWE-862 / CWE-863 (access rule now enforced)
# Date and time: 11 October 2026, 22:57, local time
# Change made: the requested ID is validated and then compared with the logged-in
#   user's identity and role before any grades are returned.
# Why it works: the decision uses the authenticated session, not the caller's
#   input, and lecturers are limited to units they are assigned to.
# Verification: In after_transcript.txt (22:57), a student requesting another
#   student's ID (Ellis, id 2) or a lecturer's ID (3) now receives "Access denied",
#   where before the patch Ellis's grade of 85.0 was returned. A non-numeric ID
#   returns "Student id must be a number".
# Functionality preserved: A student can still view their own transcript, and the
#   lecturer (Devon) and admin can still view student 1's results, as shown in
#   after_transcript.txt.
# Limitation: The lecturer rule is a design choice, because the brief does not
#   state how lecturers may access transcripts. A lecturer who is not assigned to
#   the student's units gets an empty list, while a student gets "Access denied",
#   so the two responses differ. Admins can view every transcript by design.
# Evidence: before_transcript.txt vs after_transcript.txt
def transcript(lab, student):
    require(lab)
    try:
        student_id = int(student)
    except (TypeError, ValueError):
        raise ValueError('Student id must be a number')
    user = lab['user']
    if user['role'] == 'admin':
        query = 'SELECT course,grade FROM enrolments WHERE student=?'
        params = (student_id,)
    elif user['role'] == 'lecturer':
        query = ('SELECT e.course, e.grade FROM enrolments e '
                 'JOIN courses c ON c.code = e.course '
                 'WHERE e.student=? AND c.lecturer=?')
        params = (student_id, user['id'])
    elif user['role'] == 'student' and user['id'] == student_id:
        query = 'SELECT course,grade FROM enrolments WHERE student=?'
        params = (student_id,)
    else:
        raise PermissionError('Access denied')
    return [dict(r) for r in lab['db'].execute(query, params)]

# POST-PATCH ANALYSIS
# CWE addressed: CWE-862 — Missing Authorization
# Patched by: Rabiya Begum, 750636
# Replacement signature: set_grade(lab, student, code, grade)
# Other weaknesses patched in this replacement: CWE-863
# Date and time: 11 October 2026, 13:57, local time
# Change made: require lecturer or admin role; for lecturers, also check that the
#   unit's assigned lecturer matches the logged-in user.
# Why it works: unauthorised roles are rejected before any update, and the
#   assignment check uses the courses table rather than anything the user types.
# Verification: In after_set_grade.txt (13:57), a student grading himself now
#   returns "Role not permitted", and lecturer Rowan, who teaches G04-C101,
#   grading G04-C725 returns "Not assigned to this unit". Before the patch both
#   returned "Grade updated".
# Functionality preserved: The assigned lecturer (Devon) can still grade Robin in
#   G04-C725, and the admin can still record grades. The 0–100 check and the
#   guest login check behave as before.
# Limitation: Admins can grade any unit by design, because the brief gives them
#   authority over administrative records. The assigned-unit check relies on the
#   lecturer column in the courses table being correct. Non-numeric grade or
#   student values are still rejected only by Python's conversion errors, not by
#   a dedicated friendly message.
# Evidence: before_set_grade.txt vs after_set_grade.txt

def set_grade(lab, student, code, grade):
    require(lab, 'lecturer', 'admin')
    if lab['user']['role'] == 'lecturer':
        course = lab['db'].execute('SELECT lecturer FROM courses WHERE code=?', (code,)).fetchone()
        if course is None or course['lecturer'] != lab['user']['id']:
            raise PermissionError('Not assigned to this unit')
    grade = float(grade)
    if not 0 <= grade <= 100:
        raise ValueError('Grade must be 0–100')
    with lab['db']:
        cur = lab['db'].execute('UPDATE enrolments SET grade=? WHERE student=? AND course=?', (grade, int(student), code))
    if not cur.rowcount:
        raise ValueError('Enrolment not found')
    return 'Grade updated'


# POST-PATCH ANALYSIS
# CWE addressed: CWE-306 — Missing Authentication for Critical Function
# Patched by: Rabiya Begum, 750636
# Replacement signature: set_registration(lab, code, opened)
# Other weaknesses patched in this replacement: CWE-862, CWE-20
# Date and time: 11 October 2026, 13:44, local time
# Change made: added require(lab, 'admin') as the first line and a check that
#   "opened" is exactly 0 or 1 before the database is touched.
# Why it works: require() raises PermissionError for guests and non-admins before
#   any update runs, and rejected values never reach the SQL statement.
# Verification: In after_set_registration.txt (13:44), the guest test returns
#   "Please log in" and the student test returns "Role not permitted", where before
#   the patch both returned "Registration setting updated". The values 5, -1 and
#   "abc" are now rejected with "Registration setting must be 0 (closed) or 1
#   (open)".
# Functionality preserved: admin still opens and closes units, and an unknown unit
#   still returns "Unit not found", as shown in after_set_registration.txt.
# Limitation: relies on lab['user'] being set only by a successful login; other
#   functions (such as legacy_login) can still create an admin session.
# Evidence: before_set_registration.txt vs after_set_registration.txt

def set_registration(lab, code, opened):
    require(lab, 'admin')
    value = str(opened).strip()
    if value not in ('0', '1'):
        raise ValueError('Registration setting must be 0 (closed) or 1 (open)')
    with lab['db']:
        cursor = lab['db'].execute('UPDATE courses SET open=? WHERE code=?', (int(value), code))
    if not cursor.rowcount:
        raise ValueError('Unit not found')
    return 'Registration setting updated'

# Reference: DCDCBD1B

# CWE IDENTIFICATION
# CWE ID and title: CWE-502 - Deserialization of Untrusted Data
# Student name: Jayasinghe Gunasekara, Sasanka Sanketh
# Student ID: 759596
# Date and time: 15 October 2026, 19:41 AEDT
#
# PRE-PATCH ANALYSIS
# Location: import_plan in app.py
# Function signature: import_plan(lab, filename)
# Other weaknesses in this function: CWE-770 (file/list resource limits), CWE-20 (plan
#   schema validation)
# Trigger: A student supplies a crafted pickle study-plan file.
# Root cause: pickle.load could run code before the returned course list was checked.
# Security impact: A study-plan file can execute attacker-chosen Python in the application
#   process.
# Evidence: A harmless pickle marker executed before; the same file is rejected after
#   without creating the marker.
# Affected functionality: A JSON list of valid course codes enrols the student without
#   partial updates.
#
# PATCH PLAN
# Intended change: Read a small JSON file, validate its course codes, and enrol in one
#   transaction.
# Preserved behaviour: A JSON list of valid course codes enrols the student without partial
#   updates.
#
# Original function kept for the before-and-after comparison
# def import_plan(lab, filename):
#     require(lab, 'student')
#     with open(filename, 'rb') as stream:
#         plan = pickle.load(stream)
#     if not isinstance(plan, list) or not all((isinstance(c, str) for c in plan)):
#         raise ValueError('Expected a list of course codes')
#     lab['db'].execute('BEGIN IMMEDIATE')
#     with lab['db']:
#         for code in plan:
#             _enrol(lab, code)
#     return 'Study plan imported'
#
# POST-PATCH ANALYSIS
# CWE addressed: CWE-502 - Deserialization of Untrusted Data
# Replacement signature: import_plan(lab, filename)
# Other weaknesses patched in this replacement: CWE-770 (file/list resource limits), CWE-20
#   (plan schema validation)
# Date and time: 15 October 2026, 19:41 AEDT
# Change made: Read a small JSON file, validate its course codes, and enrol in one
#   transaction.
# Why it works: The import no longer uses pickle; a bad course also rolls back the whole
#   import.
# Verification: tests/test_security.py::test_plan_deserialization_boundary and video_demo.py
#   502
# Functionality preserved: A JSON list of valid course codes enrols the student without
#   partial updates.
# Limitation: This intentionally changes the file format; do not convert an untrusted pickle
#   by loading it.
# Evidence: Assistant-run results in evidence/before_after.json; repeat locally before
#   submission.
def import_plan(lab, filename):
    _current_user(lab, 'student')
    _, content = _read_small_file(filename, ('.json',))
    try:
        plan = json.loads(content.decode('utf-8'))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError('Use a UTF-8 JSON list of course codes; pickle is not accepted') from error
    if not isinstance(plan, list) or len(plan) > MAX_PLAN_COURSES:
        raise ValueError('Expected a list of at most 200 course codes')
    if not all(isinstance(code, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,32}', code) for code in plan):
        raise ValueError('Each course code must contain 1-32 letters, numbers, underscores or hyphens')
    if len(set(plan)) != len(plan):
        raise ValueError('A study plan cannot contain duplicate course codes')
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

"""python
# CWE IDENTIFICATION
# CWE ID and title: CWE-94: Improper Control of Generation of Code
# Student name: Hrizu Sharma
# Student ID: 767643
# Identified by: Hrizu Sharma, 767643
# Date and time: 12 October 2026, 14:30, local time
#
# PRE-PATCH ANALYSIS
# Location: app.estimate function
# Function signature: estimate(lab, expression)
# Other weaknesses in this function: none identified
# Trigger: When attacker enters input expression it is accepted without validation and executes '__import__(\'os\').getpid()' 
# Root cause: The function used eval() on attacker-controlled input
# Security impact: Attacker is able to execute any arbitrary python code in lab environment
# Evidence: Attacker input was executed and function returned process information from system
# Affected functionality: Fee estimation for students

# PATCH PLAN
# Intended change: Use ast.parse() to parse the expression and only allow safe nodes.
# Preserved behaviour: Valid arithmetic expressions for credit and rate is calculated normally
"""
# def estimate(lab, expression):
#     require(lab, 'student')
#     credits = lab['db'].execute('SELECT COUNT(*) FROM enrolments WHERE student=?', (lab['user']['id'],)).fetchone()[0] * 12.5
#     return eval(expression, {'credits': credits, 'rate': 150})
"""
# POST-PATCH ANALYSIS
# CWE addressed: CWE-94: Improper Control of Generation of Code
# Patched by: Hrizu Sharma, 767643
# Replacement signature: estimate(lab, expression)
# Other weaknesses patched in this replacement: none
# Date and time: 14 October 2026,  18:36, local time
# Change made: removed the use of eval() instead AST-based evaluator which only accepts numeric credits, rate, and operators +, -, *, and / is implemented
# Why it works:  parser builds a syntax tree without executing any code and the evaluator does not allow any node type other than those explicitly listed in the allowed argument.
# Verification: User can enter only safe arithmetic, test expressions like credits*rate, invalid expressions not allowed.
# Functionality preserved: Valid arithmetic expressions for credit and rate is calculated normally
# Limitation: It can’t be trusted on unbounded input even when parsing without execution.
# Evidence: Before-invalid input: 25244 for pid was returned
# Evidence: AFter-invalid input: BLOCKED/ERROR ValueError: invalid expression
"""
def estimate(lab, expression):
    import ast, operator
    require(lab, 'student')
    if len(expression) > 40:
        raise ValueError("expression too long")

    credits = lab['db'].execute(
        'SELECT COUNT(*) FROM enrolments WHERE student=?',
        (lab['user']['id'],)
    ).fetchone()[0] * 12.5

    names = {"credits": credits, "rate": 150}
    ops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
    }

"""python
# CWE IDENTIFICATION
# CWE ID and title: CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# Student name: Hrizu Sharma
# Student ID: 767643
# Identified by: Hrizu Sharma, 767643
# Date and time: 13 October 2026, 16:14 local time
#
# PRE-PATCH ANALYSIS
# Location: app.read_document function
# Function signature: read_document(lab, filename)
# Other weaknesses in this function: none identified
# Trigger: User enters unauthorised  path ../../ for filename
# Root cause: Function joins lab['documents'] with the input filename without validation
# Security impact: Attacker is able to access arbitrary project files outside allowed directory.
# Evidence: Traversal search returned the contents of START_HERE.txt outside the allowed directory
# Affected functionality: Reading contents of documents

# PATCH PLAN
# Intended change: Parse the filename and invalidate traversal paths.
# Preserved behaviour: Accessing normal document contents works
"""
# def read_document(lab, filename):
#     require(lab)
#     return (lab['documents'] / filename).read_text(encoding='utf-8')

""" python
# POST-PATCH ANALYSIS
# CWE addressed: CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# Patched by: Hrizu Sharma, 767643
# Replacement signature: read_document(lab, filename)
# Other weaknesses patched in this replacement: none identified
# Date and time: 14 October 2026, 08:16, local time
# Change made: Normalized the path and ensured the resolved target is within documents directory
# Why it works: resolve() takes care of normalizing traversal sequences while is_relative_to() prevents the path traversed from breaking out of the allowed folder
# Verification: user can enters or attempt  traversal of '../' and they will be refused.
# Functionality preserved: Accessing normal document contents works
# Limitation: there is a race between the path check and the file read, no size or file‑type limits are enforced
# Evidence: Before-invalid input: 'KIT725 GROUP 4\nPackage: KIT725-G04-95BA8BE5\n\nOpen this folder in Visual Studio Code, then Terminal > New Terminal.\nWindows: py -3 app.py\nmacOS / Linux: python3 app.py\nKeep app.py, db_setup.py and lab_data together. Python 3.9+ is required.\n\nFictional accounts / passwords:\ng04_robin / g04_robin-lab-pass\ng04_ellis / g04_ellis-lab-pass\ng04_devon / g04_devon-lab-pass\ng04_rowan / g04_rowan-lab-pass\nadmin / admin-lab-pass\n\nRead GROUP_04.md, STUDENT_BRIEF.md and CWE_COMMENT_TEMPLATE.md.\nUse synthetic data in a disposable offline lab.\n' 
# Evidence: After-invalid input: BLOCKED/ERROR PermissionError: Traversal blocked
"""
def read_document(lab, filename):
    require(lab)
    safe_path = (lab['documents'] / filename).resolve()
    if lab['documents'] not in safe_path.parents:
        raise PermissionError("Traversal blocked")
    return safe_path.read_text(encoding='utf-8')

"""python
# CWE IDENTIFICATION
# CWE ID and title: CWE-78: Improper Neutralization of Special Elements used in an OS Command
# Student name: Hrizu Sharma
# Student ID: 767643
# Identified by: Hrizu Sharma, 767643
# Date and time: 13 October 2026, 17:43 local time
#
# PRE-PATCH ANALYSIS
# Location: app.document_count function
# Function signature: document_count(lab, pattern)
# Other weaknesses in this function: CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# Trigger: When user enters input pattern with shell characters & followed by the shell command or attempts traversal to unauthorised directory
# Root cause: The function constructed a shell command string and executed it with shell=True and pattern is passed to glob for parsing without any validation.
# Security impact: Attacker is able to execute arbitrary OS commands in lab directory
# Evidence: String "VULNERABLE" was returned due to the injected shell command and path traversed to list file count of project root directory.
# Affected functionality: Returning legit file count

# PATCH PLAN
# Intended change: Validate traversal and remove shell=True and arguments passed directly to subprocess.
# Preserved behaviour: Authentic patterns still return the correct file count
"""
# def document_count(lab, pattern):
#     require(lab, 'lecturer', 'admin')
#     helper = 'import glob,sys; print(len(glob.glob(sys.argv[1])))'
#     args = [sys.executable, '-c', helper]
#     prefix = subprocess.list2cmdline(args) if os.name == 'nt' else shlex.join(args)
#     command = prefix + ' "' + pattern + '"'
#     return subprocess.check_output(command, shell=True, cwd=lab['documents'], text=True, encoding='utf-8').strip()

"""
# POST-PATCH ANALYSIS
# CWE addressed: CWE-78: Improper Neutralization of Special Elements used in an OS Command and CWE-22: Improper Limitation of a Pathname to a Restricted Directory 
# Patched by: Hrizu Sharma, 767643
# Replacement signature: document_count(lab, pattern)
# Other weaknesses patched in this replacement: CWE-22: Improper Limitation of a Pathname to a Restricted Directory
# Date and time: 14 October 2026, 08:16, local time
# Change made: Containment check added on the glob pattern and shell=True not allowed as arguments passed directly to subprocess were removed.
# Why it works: Since shell metacharacters were not allowed it cannot trigger shell execution and the invalid code could not traverse outside document path
# Verification: Test show that no OS command can be executed and only valid patterns returns document count
# Functionality preserved: Authentic patterns still return the correct file count
# Limitation: pattern check does not prevent a symlink inside the folder from pointing outside it
# Evidence: Before-invalid input: '1\nVULNERABLE"' and invalid input: '10'
# Evidence: After-invalid input: '0' and invalid input: BLOCKED/ERROR ValueError: NOT ALLOWED
"""
def document_count(lab, pattern):
    require(lab, 'lecturer', 'admin')
    helper = 'import glob,sys; print(len(glob.glob(sys.argv[1])))'
    root = lab['documents'].resolve()
    target = (root / pattern).resolve()
    if not target.is_relative_to(root):
        raise ValueError("NOT ALLOWED")
    return subprocess.check_output([sys.executable, "-c", helper, pattern], cwd=lab['documents'], text=True, encoding='utf-8').strip()

def preview_letters(lab, copies):
    require(lab)
    letters = ['Confirmation %s: %s' % (n, lab['user']['username']) for n in range(int(copies))]
    return {'generated': len(letters), 'first': letters[:1]}

# Reference: 4840EE4E
# CWE IDENTIFICATION
# CWE ID and title: CWE-863 — Incorrect Authorization
# Student name: Rabiya Begum
# Student ID: 750636
# Identified by: Rabiya Begum, 750636
# Date and time: 11 October 2026, 14:02, local time
#
# PRE-PATCH ANALYSIS
# Location: set_course_capacity(), whole function
# Function signature: set_course_capacity(lab, code, capacity)
# Other weaknesses in this function: none
# Trigger: choose menu option 22 as a lecturer who does not teach the unit
# Root cause: require(lab, 'lecturer', 'admin') checks the role only, and the
#   function never checks that the lecturer is assigned to the unit.
# Security impact: any lecturer can change the capacity of units taught by
#   other lecturers, which can block enrolments or cause overbooking.
# Evidence: before_set_course_capacity.txt — Rowan (teaches G04-C101) changed
#   the capacity of G04-C725 and received "Course capacity updated".
# Affected functionality: setting a unit's capacity
#
# PATCH PLAN
# Intended change: for lecturers, require that the unit's assigned lecturer is
#   the logged-in user; administrators keep access to all units.
# Preserved behaviour: the assigned lecturer and admin can still set capacity,
#   the 1–200 and enrolment-floor rules remain, and unknown units still error.
#
# ORIGINAL FUNCTION (kept as commented code, not active):
# def set_course_capacity(lab, code, capacity):
#     require(lab, 'lecturer', 'admin')
#     capacity = int(capacity)
#     if not 1 <= capacity <= 200:
#         raise ValueError('Capacity must be between 1 and 200')
#     lab['db'].execute('BEGIN IMMEDIATE')
#     with lab['db']:
#         course = lab['db'].execute('SELECT code FROM courses WHERE code=?', (code,)).fetchone()
#         if course is None:
#             raise ValueError('Unit not found')
#         enrolled = lab['db'].execute(
#             'SELECT COUNT(*) FROM enrolments WHERE course=?', (code,)
#         ).fetchone()[0]
#         if capacity < enrolled:
#             raise ValueError('Capacity cannot be below current enrolments')
#         lab['db'].execute('UPDATE courses SET capacity=? WHERE code=?', (capacity, code))
#     return 'Course capacity updated'

# POST-PATCH ANALYSIS
# CWE addressed: CWE-863 — Incorrect Authorization
# Patched by: Rabiya Begum, 750636
# Replacement signature: set_course_capacity(lab, code, capacity)
# Other weaknesses patched in this replacement: none
# Date and time: 11 October 2026, 14:08, local time
# Change made: the unit query now also reads the lecturer column, and a lecturer
#   who is not the assigned lecturer is rejected inside the same transaction.
# Why it works: the decision uses the assignment stored in the courses table,
#   not anything the user types, and it runs before any update.
# Verification: In after_set_course_capacity.txt (14:08), lecturer Rowan, who
#   teaches G04-C101, setting the capacity of G04-C725 now returns "Not assigned to
#   this unit". Before the patch (14:02) the same call returned "Course capacity
#   updated".
# Functionality preserved: The assigned lecturer (Devon) and the admin can still
#   set the capacity, and the 1–200 limit, the enrolment floor and the unknown-unit
#   check behave as before.
# Limitation: Admins can change any unit by design. The check relies on the
#   lecturer column in the courses table being correct, and a non-numeric capacity
#   is still rejected only by Python's conversion error.
# Evidence: before_set_course_capacity.txt vs after_set_course_capacity.txt

def set_course_capacity(lab, code, capacity):
    require(lab, 'lecturer', 'admin')
    capacity = int(capacity)
    if not 1 <= capacity <= 200:
        raise ValueError('Capacity must be between 1 and 200')
    lab['db'].execute('BEGIN IMMEDIATE')
    with lab['db']:
        course = lab['db'].execute('SELECT code, lecturer FROM courses WHERE code=?', (code,)).fetchone()
        if course is None:
            raise ValueError('Unit not found')
        if lab['user']['role'] == 'lecturer' and course['lecturer'] != lab['user']['id']:
            raise PermissionError('Not assigned to this unit')
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

# CWE IDENTIFICATION
# CWE ID and title: CWE-434 - Unrestricted Upload of File with Dangerous Type
# Student name: Jayasinghe Gunasekara, Sasanka Sanketh
# Student ID: 759596
# Date and time: 15 October 2026, 19:41 AEDT
#
# PRE-PATCH ANALYSIS
# Location: view_submission in app.py
# Function signature: view_submission(lab, submission)
# Other weaknesses in this function: CWE-770 (the unbounded captured child output is
#   removed); this is the same upload chain, counted once.
# Trigger: An authorised viewer previews an uploaded file containing Python statements.
# Root cause: Preview passed uploaded content to the Python interpreter.
# Security impact: Student-supplied content runs code with the application process
#   privileges.
# Evidence: Before preview printed the executed marker; after it returns literal source text
#   and no process is invoked.
# Affected functionality: The owner, assigned lecturer and administrator can still preview
#   valid notes.
#
# PATCH PLAN
# Intended change: Keep the viewer permissions and decode the stored content as text
#   instead.
# Preserved behaviour: The owner, assigned lecturer and administrator can still preview
#   valid notes.
#
# Original function kept for the before-and-after comparison
# def view_submission(lab, submission):
#     require(lab)
#     row = lab['db'].execute(
#         'SELECT s.id,s.student,s.course,s.filename,s.content,c.lecturer '
#         'FROM submissions s JOIN courses c ON c.code=s.course WHERE s.id=?',
#         (int(submission),)
#     ).fetchone()
#     if row is None:
#         raise ValueError('Submission not found')
#     user = lab['user']
#     if not (user['role'] == 'admin' or
#             user['role'] == 'student' and user['id'] == row['student'] or
#             user['role'] == 'lecturer' and user['id'] == row['lecturer']):
#         raise PermissionError('Submission not available to this account')
#     with tempfile.TemporaryDirectory(prefix='coursework-') as folder:
#         uploaded = Path(folder) / 'submission'
#         uploaded.write_bytes(row['content'])
#         result = subprocess.run(
#             [sys.executable, str(uploaded)], cwd=folder, capture_output=True,
#             text=True, encoding='utf-8', errors='replace', timeout=5
#         )
#     preview = result.stdout if result.returncode == 0 else row['content'].decode('utf-8', errors='replace')
#     with lab['db']:
#         lab['db'].execute('UPDATE submissions SET preview=? WHERE id=?', (preview, row['id']))
#     record = {key: row[key] for key in ('id', 'student', 'course', 'filename')}
#     record['preview'] = preview
#     return record
#
# POST-PATCH ANALYSIS
# CWE addressed: CWE-434 - Unrestricted Upload of File with Dangerous Type
# Replacement signature: view_submission(lab, submission)
# Other weaknesses patched in this replacement: CWE-770 (the unbounded captured child output
#   is removed); this is the same upload chain, counted once.
# Date and time: 15 October 2026, 19:41 AEDT
# Change made: Keep the viewer permissions and decode the stored content as text instead.
# Why it works: Text is returned literally; preview never starts an interpreter.
# Verification: tests/test_security.py::test_coursework_never_executes and video_demo.py 434
# Functionality preserved: The owner, assigned lecturer and administrator can still preview
#   valid notes.
# Limitation: Existing incompatible stored files are rejected; no child process or sandbox
#   is needed for plain-text previews.
# Evidence: Assistant-run results in evidence/before_after.json; repeat locally before
#   submission.
def view_submission(lab, submission):
    user = _current_user(lab, 'student', 'lecturer', 'admin')
    submission_id = _read_integer(submission, 'Submission ID', 1, 9223372036854775807)
    row = lab['db'].execute(
        'SELECT s.id,s.student,s.course,s.filename,s.content,c.lecturer '
        'FROM submissions s JOIN courses c ON c.code=s.course WHERE s.id=?',
        (submission_id,)
    ).fetchone()
    if row is None:
        raise ValueError('Submission not found')
    if not (user['role'] == 'admin' or
            user['role'] == 'student' and user['id'] == row['student'] or
            user['role'] == 'lecturer' and user['id'] == row['lecturer']):
        raise PermissionError('Submission not available to this account')
    preview = _coursework_text(row['filename'], row['content'])
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
