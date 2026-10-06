"""YAML loading shared by reminders_validate.py and reminders_check.py."""
import yaml


class UniqueKeyLoader(yaml.SafeLoader):
    """safe_load that rejects a repeated mapping key instead of keeping the last one.

    PyYAML keeps the last duplicate silently, so a second top-level `credentials:` block (or a
    repeated field inside one entry) would drop the earlier entries or silently change a date.
    """

    def construct_mapping(self, node, deep=False):
        seen = set()
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if key in seen:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r} (PyYAML would silently keep the last one)",
                    key_node.start_mark)
            seen.add(key)
        return super().construct_mapping(node, deep)


def load(stream):
    return yaml.load(stream, Loader=UniqueKeyLoader)
