[ ] zimmerman/bstrings
[ ] find TLDS strings
[ ] scan bytes
   [ ] leetspeak
   [ ] suspicious guid (clsid, known folders, sandbox pids, etc)
[ ] find sddl
[ ] find oids
[ ] cli log in gui during loading screen
[ ] config
   [ ] extractor whitelist / blacklist?
   [ ] results folder location
[ ] fix navigator.clipboard is undefined
[ ] detect rtti strings including offsets
[ ] offline install (e.g. remove vt-py dependency)
[ ] detect techniques / behaviours using imports
   * like unpacking, injections, etc
   * and / or imports combinations
   * yara?
     - https://yara.readthedocs.io/en/v3.8.1/writingrules.html
     - https://github.com/xme/yara-rules/blob/main/suspicious-api-calls.yara
     - more capa rules https://github.com/mandiant/capa-rules/tree/ec223d1a1468f1d18887191ddb2e28e0a4a8e8d2
     - https://github.com/Yara-Rules/rules
   * https://fareedfauzi.github.io/2022/08/08/Malware-analysis-cheatsheet.html#winapi-process-injection-list
   * crawl c2 agents / blogs / github and extract api list
[ ] embeeded resources
  * binwalk
  * foremost
  * yara forensics https://github.com/Xumeiquer/yara-forensics/tree/a3d03742e054b71298f800793a1faada30bf2601
[ ] detect libraries
  * unique library strings
  * library third party imports (like openssl with ws32.dll and maybe psa cryptos)
[ ] install / update extractors procedure ?
   - install: e.g decrypt data during installation
   - update: update list like comp_id.txt
[ ] show images in results
  * remove stdout / stderr mechanisme
  * must output some output.json with typed ressources to display
  * or stdout.png?
  * reorganiser l'extractors_data non pas en subpath de resource mais en subpath d'extractor pour y get un map de .log et un map de .png
