control 'SV-29569' do
  title 'If the system is using LDAP for authentication or account information, the LDAP configuration file(s) must not have an extended ACL.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 

# swlist | grep LDAP

OR

# cat /etc/nsswitch.conf | sed -e 's/^[ \t]*//' | tr '\011' ' ' | tr -s ' ' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

Check the LDAP configuration file for the presence of an ACL.

# ls -alL /etc/opt/ldapux/ldapux_client.conf 

If the permissions include a "+" the file has an extended ACL, this is a finding.)
  desc 'fix', 'Remove the extended ACL from the file.
# chacl -z <LDAP configuration file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36769r4_chk'
  tag severity: 'medium'
  tag gid: 'V-22562'
  tag rid: 'SV-29569r1_rule'
  tag stig_id: 'GEN008120'
  tag gtitle: 'GEN008120'
  tag fix_id: 'F-32151r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
