control 'SV-32753' do
  title 'Server side includes (SSIs) must run with execution capability disabled.'
  desc 'The Options directive configures the web server features that are available in particular directories.  The IncludesNOEXEC feature controls the ability of the server to utilize SSIs while disabling the exec command, which is used to execute external scripts.  If the full includes feature is used it could allow the execution of malware leading to a system compromise.'
  desc 'check', 'To view the Options value enter the following command:

grep "Options" /usr/local/apache2/conf/httpd.conf. 

Review all uncommented Options statements for the following values:

+IncludesNoExec
-IncludesNoExec
-Includes 

If these values don’t exist this is a finding.

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.'
  desc 'fix', 'Edit the httpd.conf file and add one of the following to the enabled Options directive:

+IncludesNoExec
-IncludesNoExec
-Includes

Remove the ‘Includes’ or ‘+Includes’ setting from the options statement.'
  impact 0.7
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33615r1_chk'
  tag severity: 'high'
  tag gid: 'V-13733'
  tag rid: 'SV-32753r1_rule'
  tag stig_id: 'WA000-WWA054 A22'
  tag gtitle: 'WA000-WWA054'
  tag fix_id: 'F-29246r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
