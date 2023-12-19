control 'SV-33006' do
  title 'Directory indexing must be disabled on directories not containing index files.'
  desc 'Directory options directives are directives that can be applied to further restrict access to file and directories. If a URL which maps to a directory is requested, and there is no DirectoryIndex (e.g., index.html) in that directory, then mod_autoindex will return a formatted listing of the directory which is not acceptable.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: Options

Review all uncommented Options statements for the following value: -Indexes

If the value is found on the Options statement, and it does not have a preceding “-”, this is a finding. If the value does not exist, this would be a finding unless the enabled Options statement is set to “None”.'
  desc 'fix', 'Add a "-" to the Indexes setting, or set the options directive to None.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33681r1_chk'
  tag severity: 'medium'
  tag gid: 'V-13735'
  tag rid: 'SV-33006r1_rule'
  tag stig_id: 'WA000-WWA058 W22'
  tag gtitle: 'WA000-WWA058'
  tag fix_id: 'F-29307r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECSC-1'
end
