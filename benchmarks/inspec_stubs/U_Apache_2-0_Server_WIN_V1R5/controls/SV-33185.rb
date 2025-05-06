control 'SV-33185' do
  title 'The URL-path name must be set to the file path name or the directory path name.'
  desc 'The ScriptAlias directive controls which directories the Apache server "sees" as containing scripts.  If the directive uses a URL-path name that is different than the actual file system path, the potential exists to expose the script source code.'
  desc 'check', 'Locate the Apache httpd.conf file.

Open the httpd.conf file with an editor such as Notepad, and search for the following uncommented directive: ScriptAlias

If any enabled ScriptAlias directive does not have matching URL-path and file-path/directory-path entries, this is a finding.

Example:

Not a finding:

ScriptAlias /cgi-bin/ “[Drive Letter]:/[directory path]/cgi-bin/

A finding:

ScriptAlias /script-cgi-bin/ “[Drive Letter]:/[directory path]/cgi-bin/'
  desc 'fix', 'Modify the ScriptAlias directive so the URL-path and file-path/directory-path entries match.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33817r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26327'
  tag rid: 'SV-33185r1_rule'
  tag stig_id: 'WA00560 W22'
  tag gtitle: 'WA00560'
  tag fix_id: 'F-29469r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECND-1'
end
