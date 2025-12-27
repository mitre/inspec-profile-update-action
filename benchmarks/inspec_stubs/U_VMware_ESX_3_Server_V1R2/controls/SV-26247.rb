control 'SV-26247' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS key file must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check the system documentation to determine the location of the LDAP client certificate key file. Check the group owner of this file.

Procedure:
# ls -lL <key file>

If the file is not owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group owner of the LDAP client key file.

Procedure:
# chgrp root <key file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30359r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22572'
  tag rid: 'SV-26247r1_rule'
  tag stig_id: 'GEN008320'
  tag gtitle: 'GEN008320'
  tag fix_id: 'F-27123r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
