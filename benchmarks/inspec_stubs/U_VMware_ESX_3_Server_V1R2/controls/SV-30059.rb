control 'SV-30059' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf file (or equivalent) must not contain passwords.'
  desc 'The authentication of automated LDAP connections between systems must not use passwords since more secure methods are available, such as PKI and Kerberos. Additionally, the storage of unencrypted passwords on the system is not permitted.'
  desc 'check', 'Consult vendor documentation for the procedures concerning the configuration of LDAP for providing authentication and account information. Examine the LDAP configuration file(s). If the LDAP configuration file contains an unencrypted password, this is a finding. If the LDAP configuration file contains an encrypted password  accessible by regular users on the system, this is a finding.'
  desc 'fix', 'Consult vendor documentation for the procedures for configuring LDAP for authentication and account information. Remove any passwords from LDAP configuration files.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30832r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24384'
  tag rid: 'SV-30059r1_rule'
  tag stig_id: 'GEN008050'
  tag gtitle: 'GEN008050'
  tag fix_id: 'F-27446r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAIA-1, IAIA-2'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
