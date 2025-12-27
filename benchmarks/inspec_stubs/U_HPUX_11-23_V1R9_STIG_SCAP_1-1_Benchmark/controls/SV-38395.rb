control 'SV-38395' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must be group-owned by root, bin, sys, or other.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the group owner of the LDAP client key file.
# chgrp root <key file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22572'
  tag rid: 'SV-38395r1_rule'
  tag stig_id: 'GEN008320'
  tag gtitle: 'GEN008320'
  tag fix_id: 'F-32162r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
