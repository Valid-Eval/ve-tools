"""YAML loading shared by reminders_validate.py and reminders_check.py."""
import re

import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    """safe_load that rejects a repeated mapping key instead of keeping the last one.

    PyYAML keeps the last duplicate silently, so a second top-level `credentials:` block (or a
    repeated field inside one entry) would drop the earlier entries or silently change a date.
    """

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            if key_node.tag == 'tag:yaml.org,2002:merge':
                # A merge lets an explicit key shadow a merged one, or two merges shadow each other,
                # without any duplicate for this check to see. These files have no use for anchors.
                raise yaml.constructor.ConstructorError(
                    None, None, "YAML merge keys ('<<') are not supported in reminder files", key_node.start_mark)
            key = self.construct_object(key_node, deep=True)
            try:
                hash(key)
            except TypeError:
                raise yaml.constructor.ConstructorError(
                    None, None, f"unhashable mapping key {key!r}", key_node.start_mark)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r} (PyYAML would silently keep the last one)",
                    key_node.start_mark)
            seen.add(key)
        for key_node, value_node in node.value:
            if (self.construct_object(key_node, deep=True) == 'remind_days_before'
                    and value_node.tag == 'tag:yaml.org,2002:int'
                    and not re.fullmatch(r'[1-9][0-9]*', value_node.value)):
                # YAML 1.1 reads 030 as octal 24, 1:30 as base-60 90, 0x20 and 1_000 as other numbers.
                raise yaml.constructor.ConstructorError(
                    None, None, f"remind_days_before must be written as plain decimal digits (got {value_node.value!r})",
                    value_node.start_mark)
        return super().construct_mapping(node, deep)


def load(stream):
    return yaml.load(stream, Loader=UniqueKeyLoader)
