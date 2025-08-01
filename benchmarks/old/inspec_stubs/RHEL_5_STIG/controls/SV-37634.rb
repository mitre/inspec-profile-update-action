control 'SV-37634' do
  title "If the system is using LDAP for authentication or account information, the system must verify the LDAP server's certificate has not been revoked."
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires authentication.'
  desc 'fix', 'Edit "/etc/ldap.conf" and add or set the "tls_crlcheck" setting to "all".'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22558'
  tag rid: 'SV-37634r1_rule'
  tag stig_id: 'GEN008040'
  tag gtitle: 'GEN008040'
  tag fix_id: 'F-31672r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
