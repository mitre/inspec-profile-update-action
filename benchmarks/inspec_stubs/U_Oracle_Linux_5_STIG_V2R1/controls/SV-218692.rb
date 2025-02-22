control 'SV-218692' do
  title 'If the system is using LDAP for authentication or account information, certificates used to authenticate to the LDAP server must be provided from DoD PKI or a DoD-approved external PKI.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires authentication.'
  desc 'check', "Verify the source of the LDAP certificates
Check if the system is using NSS LDAP.
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.

Verify with the SA that the system is connected to the GIG.
If the system part of a standalone network which is not connected to the GIG this vulnerability is not applicable.

Verify a certificate is used for client authentication to the server.
# grep -i '^tls_cert' /etc/ldap.conf
If no line is found, this is a finding.

List the certificate issuer.
# openssl x509 -text -in <cert>
If the certificate is not issued by DoD PKI or a DoD-approved external PKI, this is a finding."
  desc 'fix', %q(Edit "/etc/ldap.conf" and add or edit the 'tls_cert' setting to reference a file containing a client certificate issued by DoD PKI or a DoD-approved external PKI.)
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20167r556493_chk'
  tag severity: 'medium'
  tag gid: 'V-218692'
  tag rid: 'SV-218692r603259_rule'
  tag stig_id: 'GEN008000'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-20165r556494_fix'
  tag 'documentable'
  tag legacy: ['V-22556', 'SV-63365']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
