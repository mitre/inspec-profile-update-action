control 'SV-37631' do
  title 'If the system is using LDAP for authentication or account information, certificates used to authenticate to the LDAP server must be provided from DoD PKI or a DoD-approved external PKI.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires authentication.'
  desc 'check', "Verify the source of the LDAP certificates
Check if the system is using NSS LDAP.
# grep -v '^#' /etc/nsswitch.conf | grep ldap
If no lines are returned, this vulnerability is not applicable.

Verify with the SA that the system is connected to the GIG.
If the system part of a stand alone network which is not connected to the GIG this vulnerability is not applicable.

Verify a certificate is used for client authentication to the server.
# grep -i '^tls_cert' /etc/ldap.conf
If no line is found, this is a finding.

List the certificate issuer.
# openssl x509 -text -in <cert>
If the certificate is not issued by DoD PKI or a DoD-approved external PKI, this is a finding."
  desc 'fix', %q(Edit "/etc/ldap.conf" and add or edit the 'tls_cert' setting to reference a file containing a client certificate issued by DoD PKI or a DoD-approved external PKI.)
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22556'
  tag rid: 'SV-37631r1_rule'
  tag stig_id: 'GEN008000'
  tag gtitle: 'GEN008000'
  tag fix_id: 'F-31668r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
