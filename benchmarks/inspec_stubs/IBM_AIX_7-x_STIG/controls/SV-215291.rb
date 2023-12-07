control 'SV-215291' do
  title 'AIX must disable Kerberos Authentication in ssh config file to enforce access restrictions.'
  desc 'Without auditing the enforcement of access restrictions against changes to the application configuration, it will be difficult to identify attempted attacks and an audit trail will not be available for forensic investigation for after-the-fact actions.

Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. Enforcement action methods may be as simple as denying access to a file based on the application of file permissions (access restriction). Audit items may consist of lists of actions blocked by access restrictions or changes identified after the fact.'
  desc 'check', %q(Check the SSH daemon configuration for the Kerberos authentication setting: 
# grep -i KerberosAuthentication /etc/ssh/sshd_config | grep -v '^#' 

If the setting is present and set to "yes", this is a finding.)
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file and add or change the "KerberosAuthentication" value of the setting to "no".

Refresh sshd:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16489r294324_chk'
  tag severity: 'medium'
  tag gid: 'V-215291'
  tag rid: 'SV-215291r853473_rule'
  tag stig_id: 'AIX7-00-002107'
  tag gtitle: 'SRG-OS-000365-GPOS-00152'
  tag fix_id: 'F-16487r294325_fix'
  tag 'documentable'
  tag legacy: ['SV-101627', 'V-91529']
  tag cci: ['CCI-001814']
  tag nist: ['CM-5 (1)']
end
