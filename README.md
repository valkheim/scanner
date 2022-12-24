# Scanner

This is a PE file static analysis engine.


## Install && run

This is a poetry-managed python project.

```
/scanner$ poetry install
/scanner$ poetry run scanner gui
 * Serving Flask app '__main__'

[...]
```

## Test release

```
/scanner$ poetry build
Building scanner (0.1.0)
  - Building sdist
  - Built scanner-0.1.0.tar.gz
  - Building wheel
  - Built scanner-0.1.0-py3-none-any.whl
/scanner$ mkdir -p /tmp/test-scanner ; cd $_
/tmp/test-scanner$ python3 -m venv .venv
/tmp/test-scanner$ . ./venv/bin/activate
(.venv) /tmp/test-scanner$ pip install /scanner/dist/scanner-0.1.0-py3-none-any.whl
(.venv) /tmp/test-scanner$ python -m scanner
 * Serving Flask app '__main__'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on http://127.0.0.1:5000
Press CTRL+C to quit
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: 119-810-875
```

## Classification

### Create classification model

```console
/scanner$ poetry run scanner classify --output_dir minimal --benigns_dir files/beningware/ --malwares_dir files/malware/
[1/10] Handle /scanner/files/malware/Backdoor.Win32.Gbot.ixz_1b2f.exe
[2/10] Handle /scanner/files/malware/Backdoor.Win32.Floder.wt_4dd0.exe
[3/10] Handle /scanner/files/malware/Backdoor.Win32.Delf.znz_2a26.exe
[4/10] Handle /scanner/files/malware/Backdoor.Win32.Bifrose.dxfg_462c.exe
[5/10] Handle /scanner/files/malware/Backdoor.Win32.Banito.br_ab19.exe
[6/10] Handle /scanner/files/malware/Backdoor.Win32.Nucleroot.jc_b1fd.exe
[7/10] Handle /scanner/files/malware/Backdoor.Win32.BlackHole.ascv_776d.exe
[8/10] Handle /scanner/files/malware/Backdoor.Win32.Agent.bhin_5e4b.exe
[9/10] Handle /scanner/files/malware/Backdoor.Win32.Poison.cmoe_fab6.exe
[10/10] Handle /scanner/files/malware/Backdoor.Win32.Hupigon.nzlf_6f76.exe
[1/10] Handle /scanner/files/beningware/87d6e92f0a8f2abac0d0287b0b80887de841e0b4
[2/10] Handle /scanner/files/beningware/calc.exe
[3/10] Handle /scanner/files/beningware/b2c0e4d1aeeae956ecafc5815d52751bd759efc2
[4/10] Handle /scanner/files/beningware/7fafe030ee923ddaec9127622ce15175f4e12782
[5/10] Handle /scanner/files/beningware/autofmt.exe
[6/10] Handle /scanner/files/beningware/1a0313ca8b44f0e0d8c9ba8281f353ec12017e21
[7/10] Handle /scanner/files/beningware/dfrgfat.exe
[8/10] Handle /scanner/files/beningware/bc9ce30bd53dba3dd4633e020f69e0a5fbc5759c
[9/10] Handle /scanner/files/beningware/36479cbc068668d8c7d3baa7a5133027dd58731d
[10/10] Handle /scanner/files/beningware/control.exe
Create random forest
Train samples: 14
Test  samples: 6
RF accuracy: 1.0
Save 'random_forest' feature importance
/scanner$ poetry run scanner classify --output_dir minimal --benigns_dir files/beningware/ --malwares_dir files/malware/
Create random forest
Train samples: 14
Test  samples: 6
RF accuracy: 1.0
Save 'random_forest' feature importance
/scanner$ ls minimal/
benign_feature_values.joblib  feature_names.joblib  malware_feature_values.joblib  random_forest_feature_importance.png  random_forest.joblib
```

You better use a larger benignware/malware collection!

Files generated:

* `random_forest.joblib`: fitted classifier dump
* `random_forest_feature_importance.png`: feature importance for that classifier

### Single file prediction

```console
/scanner$ poetry run scanner classify --classifier_path minimal/random_forest.joblib --test_file files/pe-Windows-x64-cmd
                              Feature        Value
0                   amount_of_exports     0.000000
1                   amount_of_imports   229.000000
2   amount_of_distinct_import_modules     4.000000
3                  amount_of_sections     6.000000
4                 amount_of_resources     5.000000
5               amount_of_zero_stamps     1.000000
6             amount_of_ascii_strings  1083.000000
7           amount_of_unicode_strings   140.000000
8                          has_packer     0.000000
9                    has_authenticode     0.000000
10                    has_debug_infos     1.000000
11                    has_rich_header     1.000000
12                    shannon_entropy     4.611087
13                subsystem_is_native     0.000000
14                   subsystem_is_gui     0.000000
15                   subsystem_is_cui     1.000000
files/pe-Windows-x64-cmd is benign
```

### Multiple files predictions

```console
/scanner$ poetry run scanner classify --classifier_path minimal/random_forest.joblib --test_dir files/
files/pe-Windows-ARMv7-Thumb2LE-HelloWorld is benign
files/notepad.exe is malware
files/pe-cygwin-ls.exe is benign
files/ntdll.dll is malware
files/pe-mingw32-strip.exe is benign
files/pe-Windows-x86-cmd is benign
files/pe-Windows-x64-cmd is benign
```

### Features scatter matrix

```console
/scanner$ poetry run scanner classify --output_dir minimal --scatter_matrix
Create scatter matrix
/scanner$ feh minimal/scatter_matrix.png
```

### Features correlation matrix

```console
/scanner$ poetry run scanner classify --output_dir minimal --correlation_matrix
Create correlation matrix
/scanner$ feh minimal/correlation_matrix.png
```

### Extract features of a single file

```console
/scanner$ poetry run scanner classify --dry files/pe-mingw32-strip.exe
                                                        Value
amount_of_exports                                           0
amount_of_imports                                         160
amount_of_distinct_import_modules                           5
amount_of_sections                                          8
[...]
amount_of_antidebug_functions                               0
amount_of_keyboard_functions                                0
amount_of_suspicious_functions                              0
amount_of_suspicious_modules                                0
```
