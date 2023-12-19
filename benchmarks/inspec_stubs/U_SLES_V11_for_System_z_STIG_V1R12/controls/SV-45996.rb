control 'SV-45996' do
  title 'If the system is using LDAP for authentication or account information, the system must use a TLS connection using FIPS 140-2 approved cryptographic algorithms.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires protection.'
  desc 'check', "Check if the system is using NSS LDAP. 
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.
Check if NSS LDAP is using TLS.
# grep '^ssl start_tls' /etc/ldap.conf
If no lines are returned, this is a finding.
Check if NSS LDAP TLS is using only FIPS 140-2 approved cryptographic algorithms.
# grep '^tls_ciphers' /etc/ldap.conf
If the line is not present, or contains ciphers not approved by FIPS 140-2, this is a finding."
  desc 'fix', 'Edit "/etc/ldap.conf" and add a "ssl start_tls" and "tls_ciphers" options with only FIPS 140-2 approved ciphers.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43279r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22555'
  tag rid: 'SV-45996r1_rule'
  tag stig_id: 'GEN007980'
  tag gtitle: 'GEN007980'
  tag fix_id: 'F-39362r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
