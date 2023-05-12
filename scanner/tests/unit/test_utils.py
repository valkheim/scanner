import os
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
