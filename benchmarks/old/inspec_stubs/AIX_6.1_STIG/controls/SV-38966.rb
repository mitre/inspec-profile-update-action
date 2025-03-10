control 'SV-38966' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS connection must require the server provide a certificate and this certificate has a valid trust path to a trusted CA.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Communication between an LDAP server and a host using LDAP for NSS require authentication.'
  desc 'check', "Check if the system is using LDAP authentication.
#grep LDAP /etc/security/user
If no lines are returned, this vulnerability is not applicable.

Verify SSL is enabled.
#grep '^useSSL' /etc/security/ldap/ldap.cfg
If yes is not the returned value,  this is a finding.

Verify a server certificate is required and verified by the LDAP configuration.
#grep -I  '^ldapsslkeyf' /etc/security/ldap/ldap.cfg
Make note of the key database file location.

#gsk7cmd -cert -list CA -db <certificate keyfile.kdb> -pw <Password>
Make note of the Key Label.
#gsk7cmd -cert -details -showOID -db <certificate key.kdb> -pw <Password> -label  <Key Label>

THE IBM GSK Database should only have certificates for the client system and for the LDAP server.
If more certificates are in the key database than the LDAP server and the client, this is a finding."
  desc 'fix', 'Install a certificate signed by a DoD PKI or a DoD-approved external PKI.

#gsk7cmd < or > ikeyman

Remove un-needed CA certificates.
#gsk7cmd  < or > ikeyman'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37919r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22557'
  tag rid: 'SV-38966r1_rule'
  tag stig_id: 'GEN008020'
  tag gtitle: 'GEN008020'
  tag fix_id: 'F-33175r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
