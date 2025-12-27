control 'SV-26243' do
  title 'If the system is using LDAP for authentication or account information, the LDAP TLS certificate file must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', 'Check system documentation to determine the location of the LDAP client certificate file.  Check the group ownership of the certificate file.

Procedure:
# ls -lL <certificate file>

If the file is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of the LDAP client certificate file.

Procedure:
# chgrp root <certificate file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30358r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22568'
  tag rid: 'SV-26243r1_rule'
  tag stig_id: 'GEN008240'
  tag gtitle: 'GEN008240'
  tag fix_id: 'F-27122r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
