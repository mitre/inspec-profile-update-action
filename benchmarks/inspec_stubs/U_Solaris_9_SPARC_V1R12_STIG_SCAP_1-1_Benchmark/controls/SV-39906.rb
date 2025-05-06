control 'SV-39906' do
  title 'If the system is using LDAP for authentication or account information, the LDAP configuration file must be group-owned by root, bin, or sys.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'fix', 'Change the group-owner of the files to root, bin, or sys.

Procedure:
# chgrp root /var/ldap/ldap_client_file /var/ldap/ldap_client_cred'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22561'
  tag rid: 'SV-39906r1_rule'
  tag stig_id: 'GEN008100'
  tag gtitle: 'GEN008100'
  tag fix_id: 'F-34068r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
