"""Tests for reminders_validate.py and reminders_check.py (run: python3 -m unittest discover -s .github/scripts).

Each case builds a fixture tree in a temp dir and runs the real scripts as subprocesses, the
way the workflow does. test_known_good_fixture_passes and test_repo_configs_pass assert the
validator accepts valid input, so a validator that rejects everything cannot pass this file.
"""
import ast
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

    def test_routing_only_compliance_file_without_list_key_is_fine(self):
        body = 'email_to: a@b.co\nemail_from: a@b.co\njira_project: INF\n'
        r = Fixture(reviews=body).validate()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_missing_and_non_string_routing_fields_are_rejected(self):
        for creds_or_reviews in ('reviews', 'creds'):
            base = REVIEWS if creds_or_reviews == 'reviews' else CREDS
            kw = {'reviews': base} if creds_or_reviews == 'reviews' else {'creds': base}
            self.assertRejects(Fixture(**{k: v.replace('email_from: tools@example.com\n', '') for k, v in kw.items()}),
                               "missing top-level field: 'email_from'")
            proj = 'INF' if creds_or_reviews == 'reviews' else 'VEP'
            self.assertRejects(Fixture(**{k: v.replace(f'jira_project: {proj}', 'jira_project: 123') for k, v in kw.items()}),
                               "'jira_project' must be a string")

    def test_routing_shape_is_checked_even_when_nothing_is_scheduled(self):
        body = 'email_to: not-an-email\nreviews: []\n'
        self.assertRejects(Fixture(reviews=body), "'email_to' must be an email address")

    def test_duplicate_yaml_keys_are_rejected(self):
        # PyYAML would keep the last duplicate silently, dropping the earlier entries.
        second = "credentials:\n  - name: NEW_ONE\n    description: d\n    expires: \"2026-10-10\"\n    rotation_steps: s\n"
        self.assertRejects(Fixture(creds=CREDS + second), "duplicate key 'credentials'")
        self.assertRejects(Fixture(reviews=REVIEWS + "    due: \"2026-10-21\"\n"), "duplicate key 'due'")

    def test_check_step_also_refuses_duplicate_keys(self):
        second = "credentials:\n  - name: NEW_ONE\n    description: d\n    expires: \"2026-10-10\"\n    rotation_steps: s\n"
        r, _ = Fixture(creds=CREDS + second).check()
        self.assertNotEqual(r.returncode, 0)

    def test_duplicate_name_is_rejected(self):
        dup = REVIEWS + REVIEWS.split('reviews:\n', 1)[1]
        self.assertRejects(Fixture(reviews=dup), "duplicate name")

    def test_missing_required_field_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS.replace('    description: A review\n', '')), "missing required field 'description'")

    def test_unquoted_due_date_is_rejected_with_quote_hint(self):
        self.assertRejects(Fixture(reviews=REVIEWS.replace('"2026-10-20"', '2026-10-20')), 'quote dates: "YYYY-MM-DD"')

    def test_malformed_links_are_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS.replace('INF-1', 'inf1')), "'jira_ref' must be a Jira key")
        self.assertRejects(Fixture(reviews=REVIEWS.replace('https://example.com/record', 'ftp://x')), "'compliance_ref' must be an https:// URL")

    def test_unsafe_name_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS.replace('name: some-review', 'name: "bad name!"')), "'name' must contain only")

    def test_bad_remind_days_before_is_rejected(self):
        for bad in ('0', '-1', 'true', '"3"'):
            self.assertRejects(Fixture(reviews=REVIEWS.replace('remind_days_before: 14', f'remind_days_before: {bad}')),
                               "'remind_days_before' must be a positive integer")

    def test_unparseable_or_non_mapping_files_are_fatal(self):
        r = Fixture(creds='credentials: [unclosed\n').validate()
        self.assertEqual(r.returncode, 1)
        self.assertIn('FATAL', r.stdout)
        r = Fixture(creds='- just\n- a list\n').validate()
        self.assertEqual(r.returncode, 1)
        self.assertIn('must contain a YAML mapping', r.stdout)

    def test_entry_that_is_not_a_mapping_is_rejected(self):
        self.assertRejects(Fixture(reviews=REVIEWS.split('reviews:\n')[0] + 'reviews:\n  - just a string\n'), "must be a mapping")

    def test_overdue_entry_warns_but_still_validates(self):
        r = Fixture(reviews=REVIEWS.replace('"2026-10-20"', '"2026-10-01"')).validate()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('WARNING', r.stdout)

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
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(due[0]['days_left'], 0)
        self.assertIn('0 days left', r.stdout)
        r, due = Fixture(reviews=REVIEWS.replace('"2026-10-20"', '"2026-10-05"')).check()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(due[0]['days_left'], -1)
        self.assertIn('OVERDUE (1 days ago)', r.stdout)

    def test_credential_expiring_today_is_logged_as_expired(self):
        r, _ = Fixture(creds=CREDS.replace('"2027-01-01"', '"2026-10-06"')).check()
        self.assertIn('EXPIRED (0 days ago)', r.stdout)

    def test_default_window_is_15_days(self):
        # No remind_days_before on the credential: due 15 days out, not 16.
        self.assertEqual(self.due_names(Fixture(creds=CREDS.replace('"2027-01-01"', '"2026-10-21"'), reviews=None)), ['SOME_TOKEN'])
        self.assertEqual(self.due_names(Fixture(creds=CREDS.replace('"2027-01-01"', '"2026-10-22"'), reviews=None)), [])

    def test_github_output_heredoc_and_has_due_flag(self):
        # The notify step is gated on has_due and reads result; parse the file as the runner does.
        def parse(fixture):
            fixture.check()
            with open(os.path.join(fixture.dir.name, 'gh_output')) as f:
                lines = f.read().splitlines()
            self.assertTrue(lines[0].startswith('result<<ghadelimiter_'))
            delim = lines[0].split('<<', 1)[1]
            end = lines.index(delim, 1)
            return json.loads('\n'.join(lines[1:end])), dict(l.split('=', 1) for l in lines[end + 1:])
        result, flags = parse(Fixture())
        self.assertEqual(flags['has_due'], 'true')
        self.assertEqual([d['name'] for d in result['due']], ['some-review'])
        result, flags = parse(Fixture(reviews=REVIEWS.replace('"2026-10-20"', '"2026-10-21"')))
        self.assertEqual(flags['has_due'], 'false')
        self.assertEqual(result['due'], [])

    def test_sources_tables_agree(self):
        # reminders_validate.py and reminders_check.py each carry a SOURCES table; drift between
        # them would let validate pass a file that check then cannot read.
        def sources(name):
            with open(os.path.join(SCRIPTS, name)) as f:
                tree = ast.parse(f.read())
            for node in tree.body:
                if isinstance(node, ast.Assign) and node.targets[0].id == 'SOURCES':
                    return ast.literal_eval(node.value)
        validate = [(p, key, df) for p, key, _, df, _ in sources('reminders_validate.py')]
        check = [(p, key, df) for p, key, _, df, _ in sources('reminders_check.py')]
        self.assertEqual(validate, check)

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
