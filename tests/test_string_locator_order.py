import unittest

from dex_fixture import make_dex, reorder_string_data
from droidasc.asc_client.asc_handler import AscHandler
from droidasc.asc_core.findrefs.locator.string_locator import StringLocator
from droidasc.asc_core.utils.tinydex import DEX


# the string table of dex_fixture.make_dex(), in string_ids order
STRINGS = {
    'Lexample/Test;': 0,
    'Ljava/lang/Object;': 1,
    'V': 2,
    'first': 3,
    'second': 4,
    'token': 5,
}
INDEX_ORDER = [0, 1, 2, 3, 4, 5]
REVERSED = [5, 4, 3, 2, 1, 0]
MIDDLE = [0, 5, 4, 3, 2, 1]


class StringLayoutTests(unittest.TestCase):
    def dex(self, data):
        return DEX.parse(memoryview(data), 'layout.dex')

    def assert_layout(self, data):
        locator = StringLocator(self.dex(data))
        for text, idx in STRINGS.items():
            with self.subTest(text=text):
                self.assertEqual(locator.locate(text), {idx})

    def test_permutation_keeps_the_string_table(self):
        # the layouts below must only move bytes around: every index has to keep
        # naming the same string, otherwise the tests would pass on a broken fixture
        for order in (INDEX_ORDER, REVERSED, MIDDLE):
            with self.subTest(order=order):
                dex = self.dex(reorder_string_data(make_dex(), order))
                self.assertEqual(
                    [dex.get_string(idx) for idx in range(len(STRINGS))],
                    list(STRINGS),
                )

    def test_index_order_layout(self):
        self.assert_layout(make_dex())

    def test_reversed_layout(self):
        self.assert_layout(reorder_string_data(make_dex(), REVERSED))

    def test_middle_permutation(self):
        self.assert_layout(reorder_string_data(make_dex(), MIDDLE))

    def test_substring_maps_to_the_item_that_holds_it(self):
        # 'oken' only appears inside 'secret-token', whose index is 5
        self.assertEqual(
            StringLocator(self.dex(reorder_string_data(make_dex(), REVERSED)))
            .locate('oken'),
            {5},
        )

    def test_match_across_two_items_names_no_string(self):
        # 'first' and 'second' are neighbours on disk, but a match may not run from
        # one item through the terminator into the next
        self.assertEqual(StringLocator(self.dex(make_dex())).locate('first\x00second'), set())

    def test_findrefs_matches_the_index_order_layout(self):
        handler = AscHandler()
        expected = handler.findrefs(
            'fixture.dex', make_dex(), 'string', {'string': 'token'})
        reordered = handler.findrefs(
            'fixture.dex',
            reorder_string_data(make_dex(), REVERSED),
            'string',
            {'string': 'token'},
        )
        self.assertEqual(reordered, expected)
        self.assertEqual(len(expected), 2)


if __name__ == '__main__':
    unittest.main()
