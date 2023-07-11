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
