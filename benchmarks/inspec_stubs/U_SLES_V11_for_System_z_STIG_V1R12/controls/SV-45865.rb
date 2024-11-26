control 'SV-45865' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf file (or equivalent) must not contain passwords.'
  desc 'The authentication of automated LDAP connections between systems must not use passwords since more secure methods are available, such as PKI and Kerberos. Additionally, the storage of unencrypted passwords on the system is not permitted.'
  desc 'check', 'Check for the "bindpw" option being used in the "/etc/ldap.conf" file.

# grep bindpw /etc/ldap.conf
If an uncommented "bindpw" option is returned then a cleartext password is in the file, this is a finding.'
  desc 'fix', 'Edit the "/etc/ldap.conf" file to use anonymous binding by removing the "bindpw" option.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43160r2_chk'
  tag severity: 'medium'
  tag gid: 'V-24384'
  tag rid: 'SV-45865r1_rule'
  tag stig_id: 'GEN008050'
  tag gtitle: 'GEN008050'
  tag fix_id: 'F-39245r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
