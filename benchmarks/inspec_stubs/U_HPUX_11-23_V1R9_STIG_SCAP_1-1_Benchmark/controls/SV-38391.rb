control 'SV-38391' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must be group-owned by root, bin, sys, or other.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the group ownership of the LDAP client certificate file.
# chgrp root <cert file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-22568'
  tag rid: 'SV-38391r1_rule'
  tag stig_id: 'GEN008240'
  tag gtitle: 'GEN008240'
  tag fix_id: 'F-32158r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
