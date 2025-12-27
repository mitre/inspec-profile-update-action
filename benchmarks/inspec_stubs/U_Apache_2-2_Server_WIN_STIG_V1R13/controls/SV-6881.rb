control 'SV-6881' do
  title 'The access control files are owned by a privileged web server account.'
  desc 'This check verifies that the key web server system configuration files are owned by the SA or Web Manager controlled account. These same files which control the configuration of the web server, and thus its behavior, must also be accessible by the account which runs the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform.'
  desc 'check', 'If .htaccess or the .htaccess.html files are in use, the SA or Web Manager account may have Full Control, the non-privileged web server account running the web service should have read and execute permissions. 

Right click the .htaccess.html  file, if present. Select the Properties window, select the Security tab. Examine the access rights for the file.  The SA or Web Manager account should have Full Control, the account running the web service should have read and execute permissions.

If entries other than Administrators, the Web Manager accounts, or System for any degree of access are present, this is a finding.'
  desc 'fix', 'The site needs to ensure that the owner should be the non-privileged web server account or equivalent which runs the web service; however, the group permissions represent those of the user accessing the web site that must execute the directives in .htacces.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-2679r2_chk'
  tag severity: 'medium'
  tag gid: 'V-2256'
  tag rid: 'SV-6881r1_rule'
  tag stig_id: 'WG280'
  tag gtitle: 'WG280'
  tag fix_id: 'F-6762r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Web Administrator']
end
