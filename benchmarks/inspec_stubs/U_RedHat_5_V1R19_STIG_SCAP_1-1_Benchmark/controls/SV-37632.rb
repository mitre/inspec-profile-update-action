control 'SV-37632' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS connection must require the server provide a certificate with a valid trust path to a trusted CA.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Communication between an LDAP server and a host using LDAP for NSS require authentication.'
  desc 'fix', 'Edit "/etc/ldap.conf" and add or set the "tls_checkpeer" setting to "yes".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22557'
  tag rid: 'SV-37632r1_rule'
  tag stig_id: 'GEN008020'
  tag gtitle: 'GEN008020'
  tag fix_id: 'F-31669r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
