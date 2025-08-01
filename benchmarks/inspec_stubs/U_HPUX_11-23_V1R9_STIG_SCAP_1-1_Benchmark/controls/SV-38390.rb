control 'SV-38390' do
  title 'For systems using NSS LDAP, the TLS certificate file must be owned by root.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Its configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the ownership of the file.
# chown root <certfile>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22567'
  tag rid: 'SV-38390r1_rule'
  tag stig_id: 'GEN008220'
  tag gtitle: 'GEN008220'
  tag fix_id: 'F-32157r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
