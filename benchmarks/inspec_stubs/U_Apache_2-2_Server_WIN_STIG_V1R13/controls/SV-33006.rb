control 'SV-33006' do
  title 'Directory indexing must be disabled on directories not containing index files.'
  desc 'Directory options directives are directives that can be applied to further restrict access to file and directories. 
If a URL which maps to a directory is requested, and there is no DirectoryIndex (e.g., index.html) in that directory, then mod_autoindex will return a formatted listing of the directory. 
The Indexes option allows for the functionality of presenting a formatted listing of the directory.
Returning a formatted listing of the directory represents a vulnerability since it will allow an attacker to have knowledge of the directory contents and potentially gather sensitive information.
To explicitly disable an Options functionality, the option must be listed on every uncommented Options directive with a preceding the option. The "-" preceding the option configures Apache to explicitly disable the option. An Options directive with "none" will also disable the functionality.
If the option is listed on an Options directive line without a preceding - or without anything preceding it or with a "+" preceding it or not configured at all, the Indexes option is enabled and is vulnerable.'
  desc 'check', 'Open the httpd.conf file with an editor such as Notepad, and search for all occurrences of the following directive: Options.

This check validates occurrences of the Options directive which are uncommented.
Review all uncommented Options statements for "-Indexes" and validate a preceding "-" to the Indexes option exists.

If the value is found on the Options statement, and it does not have a preceding "-", this is a finding. 
If the value does not exist at all, this would be a finding unless the enabled Options statement is set to "none".'
  desc 'fix', 'Add a "-" to the Indexes setting, or set the options directive to None.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33681r2_chk'
  tag severity: 'medium'
  tag gid: 'V-13735'
  tag rid: 'SV-33006r2_rule'
  tag stig_id: 'WA000-WWA058 W22'
  tag gtitle: 'WA000-WWA058'
  tag fix_id: 'F-29307r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
