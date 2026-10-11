# University Course Registration System

A Python console application for managing accounts, unit enrolments, results and university administration. SQLite stores the application data locally.

Use only synthetic data in a disposable offline lab, without administrator privileges.

## Start in Visual Studio Code

Open this folder, then select Terminal → New Terminal. Python 3.9 or later with the standard sqlite3 module is required. No external packages are needed.

| Operation | Windows | macOS / Linux |
|---|---|---|
| Run source | `py -3 app.py` | `python3 app.py` |

Use `python` on Windows if the `py` launcher is unavailable.  The package has been tested on macOS; check normal workflows on your own operating system.

## Sample accounts

| Username | Password | Role | ID |
|---|---|---|---|
| g04_robin | g04_robin-lab-pass | Student | 1 |
| g04_ellis | g04_ellis-lab-pass | Student | 2 |
| g04_devon | g04_devon-lab-pass | Lecturer | 3 |
| admin | admin-lab-pass | Administrator | 4 |
| g04_rowan | g04_rowan-lab-pass | Lecturer | 5 |

Choose a menu number and enter the requested values. Login password entry is visible for the labelled worked example; its commented alternative hides input. Other password prompts remain hidden. Select 0 to exit. Data persists in lab_data; use `--data-dir another_lab` for a fresh dataset.

## Business context

Students manage their own enrolments and view their own results. Lecturers manage academic results and course capacities for their assigned units. Administrators manage all units, registration and administrative records. Personal records are confidential. In a fresh dataset, Devon teaches G04-C725 and Rowan teaches G04-C101. Robin and Ellis initially take G04-C725. Existing datasets retain their accounts and teaching assignments; use the supplied fresh database to follow these examples.

Option 22 updates a course capacity. Capacities must be between 1 and 200 and cannot be below the number of existing enrolments.

Try searching for Programming, enrolling Robin in G04-C101, viewing her transcript, and withdrawing from that unit. A fee estimate can use `credits * rate`; the sample document is g04-handbook.txt.

Coursework for these units consists of UTF-8 text notes in .txt or .md files, up to 64 KiB. Select 20 to submit a file for a unit you are enrolled in. Enter its local file path without surrounding quotation marks. The application stores the submission and returns a submission ID. Select 21 to preview it. The submitting student, the assigned lecturer and administrators can view the submission. A sample text file is available at lab_data/g04-coursework.txt.

## Analysis task

Analyse the implementation and follow the supplied assignment specification for evidence, reporting and individual contributions. Preserve legitimate workflows when making changes. Create tests for normal and unexpected inputs. Document any justified interface or data-format changes and update the corresponding tests.

## Overall patching instructions

These rules apply to every CWE addressed in the individual component:

1. Identify the complete function in which the weakness occurs and record its exact function name and parameter signature.
2. Create a patched replacement with the same function name and the same parameter signature. The surrounding application must continue to call the function without interface changes.
3. Keep the original and replacement versions clearly separated, with only one version active when the program is run and tested.
4. A function may contain multiple weaknesses. When it does, the replacement function must address every weakness identified in that function, not only the CWE assigned to one student.
5. Demonstrate each weakness before the patch and repeat the relevant tests after enabling the complete replacement.
6. Show that the patched function removes the security problem while preserving the normal feature.
7. If multiple students identify weaknesses in the same function, coordinate the work and submit one complete replacement for that function.

Application accounts define the scope of the exercise. Direct editing of the underlying database using the operating system account is outside that scope.

## Code structure

Application workflows are in app.py; db_setup.py prepares the database and sample files. It uses ordinary functions, dictionaries, conditionals and loops; there are no custom classes or inheritance. Functions receive a lab dictionary containing the database connection, file locations and current login state. Keep db_setup.py alongside app.py.

Fee adjustments accept an optional reference. Reuse it to retry the same adjustment or leave it blank to record a new adjustment each time.

## Group package identifiers

This package is assigned to Group 4. See GROUP_04.md for membership. Preserve the Teaching package and Reference comments when editing or copying functions into the patched version. These identify the issued package and do not identify assessment answers. Use only this group dataset for demonstrations.
