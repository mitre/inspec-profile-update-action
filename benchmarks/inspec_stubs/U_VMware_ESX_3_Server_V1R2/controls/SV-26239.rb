control 'SV-26239' do
  title 'If the system is using LDAP for authentication or account information, the TLS certificate authority file and/or directory (as appropriate) must be group-owned by root, bin, sys, or system.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification'
  desc 'check', 'Consult system documentation to determine where the LDAP client certificate files are stored.  Check their group ownership.

Procedure:
# ls -lLa <ldap certificate file(s) or directories>

If a certificate file or directory is not group-owned by root, bin, sys, or system, this is a finding.'
  desc 'fix', 'Change the group ownership of LDAP client certificate files to root, bin, sys, or system.

Procedure:
# chgrp root <certificate file>'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-30357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22564'
  tag rid: 'SV-26239r1_rule'
  tag stig_id: 'GEN008160'
  tag gtitle: 'GEN008160'
  tag fix_id: 'F-27121r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
