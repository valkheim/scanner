import unittest
import unittest.mock

from scanner import analyse

from . import utils


class TestAnalyse(unittest.TestCase):
    def test_yield_extractor_paths(self) -> None:
        extractor_paths = list(
            analyse.yield_extractor_paths(
                utils.get_some_golden_result(), mkdir=False
            )
        )
        suffixes = [
            extractor_path.split("extractors")[-1]
            for extractor_path, _ in extractor_paths
        ]
        got = sorted(suffixes)
        expected = [
            r"/capa/flare_capa.py",
            r"/checksums/checksums.sh",
            r"/entropy/entropy.py",
            r"/identification/file.sh",
            r"/pe/authenticode.py",
            r"/pe/debug.py",
            r"/pe/exports.py",
            r"/pe/features.py",
            r"/pe/header.py",
            r"/pe/imports.py",
            r"/pe/imports_hash.py",
            r"/pe/packers.py",
            r"/pe/resources.py",
            r"/pe/rich_header.py",
            r"/pe/sections.py",
            r"/pe/stamps.py",
            r"/pe/subsystem.py",
            r"/pe/suspicious_imports.py",
            r"/pe/suspicious_modules.py",
            r"/pe/suspicious_sections.py",
            r"/strings/ascii.py",
            r"/strings/domain_names.py",
            r"/strings/ipv4.py",
            r"/strings/stack_strings.sh",
            r"/strings/suspicious_strings.py",
            r"/strings/tight_strings.sh",
            r"/strings/unicode.py",
            r"/vt/by_hash.py",
        ]
        self.assertListEqual(got, expected)

    def test_get_extractors_data(self) -> None:
        some_golden_dir = utils.get_some_golden_result(
            "f2cd2b349341094854c5806f617a746dd50a74eb"
        )
        extractors_data = analyse.get_extractors_data(some_golden_dir)
        expected = [
            r"checksums/checksums/stdout.log",
            r"entropy/entropy/stdout.log",
            r"identification/file/stdout.log",
            r"strings/ascii/stdout.log",
            r"strings/suspicious_strings/stdout.log",
            r"strings/unicode/stdout.log",
        ]
        got = sorted(list(extractors_data.keys()))
        self.assertListEqual(got, expected)
        self.assertTrue(
            r"pe-Windows-x86-cmd: PE32 executable (console) Intel 80386, for MS Windows, 4 sections"
            in extractors_data["identification/file/stdout.log"]
        )

    @unittest.mock.patch("scanner.analyse.get_results_dir")
    def test_get_result(self, mock: unittest.mock.Mock) -> None:
        mock.return_value = utils.get_golden_results_dir()
        infos = analyse.get_result(r"f2cd2b349341094854c5806f617a746dd50a74eb")
        self.assertIsNotNone(infos)
        self.assertEqual(sorted(infos.keys()), ["extractors", "infos"])
        self.assertEqual(infos["infos"]["filename"], "pe-Windows-x86-cmd")
