control 'SV-37643' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf file (or equivalent) must not contain passwords.'
  desc 'The authentication of automated LDAP connections between systems must not use passwords since more secure methods are available, such as PKI and Kerberos. Additionally, the storage of unencrypted passwords on the system is not permitted.'
  desc 'fix', 'Edit the "/etc/ldap.conf" file to use anonymous binding by removing the "bindpw" option.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-24384'
  tag rid: 'SV-37643r3_rule'
  tag stig_id: 'GEN008050'
  tag gtitle: 'GEN008050'
  tag fix_id: 'F-31678r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
