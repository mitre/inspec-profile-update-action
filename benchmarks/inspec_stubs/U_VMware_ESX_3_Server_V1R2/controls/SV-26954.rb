control 'SV-26954' do
  title 'For systems using NSS LDAP, the TLS certificate file must be owned by root.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Its configuration must be protected from unauthorized modification.'
  desc 'check', "Determine the certificate file.
# grep -i '^tls_cert' /etc/ldap.conf
Check the ownership.
# ls -lL <certpath>
If the owner of the file is not root, this is a finding."
  desc 'fix', 'Change the ownership of the file.
# chown root <certpath>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27901r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22567'
  tag rid: 'SV-26954r1_rule'
  tag stig_id: 'GEN008220'
  tag gtitle: 'GEN008220'
  tag fix_id: 'F-24216r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
