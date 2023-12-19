control 'SV-38381' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS connection must require the server provide a certificate and this certificate has a valid trust path to a trusted CA.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Communication between an LDAP server and a host using LDAP for NSS require authentication.'
  desc 'fix', 'Edit /etc/opt/ldapux/ldapux_client.conf and set

# Perform the CERT check
peer_cert_policy=CERT

OR 

# Perform the CERT check PLUS
peer_cert_policy=CNCERT'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22557'
  tag rid: 'SV-38381r1_rule'
  tag stig_id: 'GEN008020'
  tag gtitle: 'GEN008020'
  tag fix_id: 'F-32145r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
