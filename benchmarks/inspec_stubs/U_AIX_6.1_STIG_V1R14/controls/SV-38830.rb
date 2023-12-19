control 'SV-38830' do
  title 'If the system is using LDAP for authentication or account information, certificates used to authenticate to the LDAP server must be provided from DoD PKI or a DoD-approved external PKI.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires authentication.'
  desc 'check', "Check if the system is using LDAP authentication.
 
#grep LDAP /etc/security/user
If no lines are returned, this vulnerability is not applicable.

Check if the useSSL option is enabled.
#grep '^useSSL' /etc/security/ldap/ldap.cfg
If yes is not the returned value,  this is a finding.

Verify a certificate is used for client authentication to the server.
#grep -I  '^ldapsslkeyf' /etc/security/ldap/ldap.cfg
If no line is found, this is a finding.

List the certificate issuer with IBM GSK.
#gsk7cmd -cert -list CA -db <certificate keyfile.kdb> -pw <Password>

Make note of the client Key Label.
#gsk7cmd -cert -details -showOID -db <certificate key.kdb> -pw <Password> -label  <Key Label>

If the certificate is not issued by DoD PKI or a DoD-approved external PKI, this is a finding."
  desc 'fix', 'Create a key database with DoD PKI or DoD-approved  certificate.

#gsk7cmd 
OR
#ikeyman

Edit /etc/security/ldap/ldap.conf and add or edit the ldapsslkeyf setting to reference a file containing a client certificate issued by DoD PKI or a DoD-approved external PKI.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22556'
  tag rid: 'SV-38830r1_rule'
  tag stig_id: 'GEN008000'
  tag gtitle: 'GEN008000'
  tag fix_id: 'F-32355r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
