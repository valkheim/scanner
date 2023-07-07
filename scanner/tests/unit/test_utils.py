import os
import tempfile
import unittest
import unittest.mock

from scanner import utils


class TestUtils(unittest.TestCase):
    @unittest.mock.patch("os.makedirs")
    def test_get_results_dir_without_hash(
        self, mock: unittest.mock.Mock
    ) -> None:
        package_basedir = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )
        expected_dir = os.path.join(package_basedir, "results")
        self.assertEqual(utils.get_results_dir(), expected_dir)
        mock.assert_called_with(expected_dir, exist_ok=True)

    @unittest.mock.patch("os.makedirs")
    def test_get_results_dir_with_hash(self, mock: unittest.mock.Mock) -> None:
        package_basedir = os.path.normpath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )
        expected_dir = os.path.join(package_basedir, "results", "hash")
        self.assertEqual(utils.get_results_dir("hash"), expected_dir)
        mock.assert_called_with(expected_dir, exist_ok=True)

    def test_resolve_extractor_path(self) -> None:
        path = utils.resolve_extractor_path("entropy/entropy/stdout.log")
        self.assertTrue(
            path.endswith(r"/scanner/extractors/entropy/entropy.py")
        )

    def test_hexdump(self) -> None:
        data = b"ABCDEF012345678\x00"
        got = utils.hexdump(data)
        expected = "0x000000: 41 42 43 44 45 46 30 31  32 33 34 35 36 37 38 00 |ABCDEF012345678.|"
        self.assertIsNotNone(got)
        self.assertEqual(got, expected)

    @unittest.mock.patch("scanner.utils.zipfile.ZipFile")
    @unittest.mock.patch("scanner.utils.get_results_dir")
    def test_archive(self, get_results_dir, zipfile) -> None:
        with tempfile.TemporaryDirectory() as tmpd:
            get_results_dir.return_value = tmpd
            expected_archive_path = os.path.join(
                tmpd, "scanner-hash-timestamp.zip"
            )
            got_archive_path = utils.archive(
                "hash", {"last_update": "timestamp"}
            )
            self.assertEqual(got_archive_path, expected_archive_path)
            zipfile.assert_called_once_with(
                expected_archive_path, "w", compression=12, compresslevel=9
            )
