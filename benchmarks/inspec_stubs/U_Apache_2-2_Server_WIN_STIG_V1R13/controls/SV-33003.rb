control 'SV-33003' do
  title 'Server side includes (SSIs) must run with execution capability disabled.'
  desc 'The Options directive configures the web server features that are available in particular directories.  The IncludesNOEXEC feature controls the ability of the server to utilize SSIs while disabling the exec command, which is used to execute external scripts.  If the full includes feature is used it could allow the execution of malware leading to a system compromise.'
  desc 'check', 'Locate the Apache httpd.conf file.

If unable to locate the file, perform a search of the system to find the location of the file.

Open the httpd.conf file with an editor such as notepad, and search for the following uncommented directive: Options

Review all uncommented Options statements for the following values: +IncludesNoExec, -IncludesNoExec, or -Includes

If these values are found on an enabled Options statement, this is not a finding. If these values do not exist at all, this would be a finding unless the enabled Options statement is set to “None”. If any enabled Options statement has "Includes” or "+Includes” as part of its statement, this is a finding.'
  desc 'fix', 'Add one of the following to the enabled Options directive +IncludesNoExec, -IncludesNoExec, or -Includes. Remove the "Includes" or "+Includes" setting from the options statement.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33670r1_chk'
  tag severity: 'high'
  tag gid: 'V-13733'
  tag rid: 'SV-33003r1_rule'
  tag stig_id: 'WA000-WWA054 W22'
  tag gtitle: 'WA000-WWA054'
  tag fix_id: 'F-29305r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
