"""Tests for reminders_validate.py and reminders_check.py (run: python3 -m unittest discover -s .github/scripts).

Each case builds a fixture tree in a temp dir and runs the real scripts as subprocesses, the
way the workflow does. Every rejection case is paired with the known-good fixture passing, so a
validator that rejects everything cannot pass this file.
"""
import atexit
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(SCRIPTS))
TODAY = '2026-10-06'

CREDS = """\
email_to: tools@example.com
email_from: tools@example.com
jira_project: VEP
credentials:
  - name: SOME_TOKEN
    description: A token
    expires: "2027-01-01"
    rotation_steps: |-
      1. Rotate it
"""

REVIEWS = """\
email_to: tools@example.com
email_from: tools@example.com
jira_project: INF
reviews:
  - name: some-review
    description: A review
    due: "2026-10-20"
    remind_days_before: 14
    steps: |-
      1. Review it
    compliance_ref: https://example.com/record
    jira_ref: INF-1
"""


class Fixture:
    def __init__(self, creds=CREDS, reviews=REVIEWS):
        self.dir = type('D', (), {'name': tempfile.mkdtemp()})()
        atexit.register(shutil.rmtree, self.dir.name, True)
        os.makedirs(os.path.join(self.dir.name, '.github'))
        self.write('credential-rotations.yml', creds)
        if reviews is not None:
            self.write('compliance-reviews.yml', reviews)

    def write(self, name, text):
        with open(os.path.join(self.dir.name, '.github', name), 'w') as f:
            f.write(text)

    def run(self, script, **env):
        e = dict(os.environ, REMINDERS_ROOT=self.dir.name, REMINDERS_TODAY=TODAY, **env)
        return subprocess.run([sys.executable, os.path.join(SCRIPTS, script)],
                              capture_output=True, text=True, env=e)

    def validate(self):
        return self.run('reminders_validate.py')

    def check(self, **env):
        out = os.path.join(self.dir.name, 'gh_output')
        r = self.run('reminders_check.py', GITHUB_OUTPUT=out, **env)
        result = None
        if os.path.exists(out):
            with open(out) as f:
                text = f.read()
            line = next(l for l in text.splitlines() if l.startswith('{'))
            result = json.loads(line)['due']
        return r, result


class ValidateTests(unittest.TestCase):
    def assertRejects(self, fixture, needle):
        r = fixture.validate()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(needle, r.stdout)

    def test_known_good_fixture_passes(self):
        r = Fixture().validate()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_repo_configs_pass(self):
        e = dict(os.environ, REMINDERS_ROOT=REPO, REMINDERS_TODAY=TODAY)
        r = subprocess.run([sys.executable, os.path.join(SCRIPTS, 'reminders_validate.py')],
                           capture_output=True, text=True, env=e)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_absent_empty_and_empty_list_compliance_files_are_fine(self):
        for reviews in (None, '', '# nothing scheduled\n', 'reviews: []\n'):
            r = Fixture(reviews=reviews).validate()
            self.assertEqual(r.returncode, 0, f"{reviews!r}: {r.stdout}{r.stderr}")

    def test_misspelled_list_key_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS.replace('reviews:', 'reviewz:')), "unknown top-level key")

    def test_null_list_is_rejected(self):
        body = 'email_to: a@b.co\nemail_from: a@b.co\njira_project: INF\nreviews:\n'
        self.assertRejects(Fixture(reviews=body), "reviews: []")

    def test_unquoted_date_in_notes_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS + "    notes: 2026-10-01\n"), "'notes' must be a string")

    def test_unknown_entry_key_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS + "    remind_day_before: 3\n"), "unknown key")

    def test_bad_routing_values_are_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS.replace('email_to: tools@example.com', 'email_to: not-an-email')),
                           "'email_to' must be an email address")
        self.assertRejects(Fixture(reviews=REVIEWS.replace('jira_project: INF', 'jira_project: inf')),
                           "'jira_project' must be an uppercase Jira project key")

    def test_bad_priority_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS + "    jira_priority: Urgent\n"), "'jira_priority' must be one of")
        r = Fixture(reviews=REVIEWS + "    jira_priority: High\n").validate()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_compact_date_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS.replace('"2026-10-20"', '"20261020"')), "not a valid ISO date")

    def test_credentials_file_is_held_to_the_same_rules(self):
        self.assertRejects(Fixture(creds=CREDS.replace('credentials:', 'credentialz:')), "unknown top-level key")
        self.assertRejects(Fixture(creds=CREDS + "    notes: 2026-10-01\n"), "'notes' must be a string")


class CheckTests(unittest.TestCase):
    def due_names(self, fixture, **env):
        r, due = fixture.check(**env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return [d['name'] for d in due]

    def test_review_inside_window_is_due(self):
        # due 2026-10-20, remind 14 days before: exactly 14 days left on TODAY
        self.assertEqual(self.due_names(Fixture()), ['some-review'])

    def test_review_one_day_outside_window_is_not_due(self):
        r = Fixture(reviews=REVIEWS.replace('"2026-10-20"', '"2026-10-21"'))
        self.assertEqual(self.due_names(r), [])

    def test_due_today_is_zero_days_left_and_overdue_is_negative(self):
        r, due = Fixture(reviews=REVIEWS.replace('"2026-10-20"', '"2026-10-06"')).check()
        self.assertEqual(due[0]['days_left'], 0)
        r, due = Fixture(reviews=REVIEWS.replace('"2026-10-20"', '"2026-10-05"')).check()
        self.assertEqual(due[0]['days_left'], -1)

    def test_each_kind_gets_its_own_routing_and_refs(self):
        r, due = Fixture(creds=CREDS.replace('"2027-01-01"', '"2026-10-10"')).check()
        by = {d['name']: d for d in due}
        self.assertEqual(by['SOME_TOKEN']['jira_project'], 'VEP')
        self.assertEqual(by['SOME_TOKEN']['kind'], 'credential')
        self.assertEqual(by['some-review']['jira_project'], 'INF')
        self.assertEqual(by['some-review']['kind'], 'compliance_review')
        self.assertEqual(by['some-review']['jira_ref'], 'INF-1')

    def test_test_credential_bypasses_the_date_check(self):
        r, due = Fixture().check(TEST_CREDENTIAL='TEST_CREDENTIAL')
        self.assertEqual([d['name'] for d in due], ['TEST_CREDENTIAL'])
        self.assertTrue(due[0]['is_test'])

    def test_absent_compliance_file_leaves_credential_reminders_working(self):
        r = Fixture(creds=CREDS.replace('"2027-01-01"', '"2026-10-10"'), reviews=None)
        self.assertEqual(self.due_names(r), ['SOME_TOKEN'])


if __name__ == '__main__':
    unittest.main()
