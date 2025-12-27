control 'SV-38384' do
  title 'If the system is using LDAP for authentication or account information, the /etc/ldap.conf (or equivalent) file must be owned by root or bin.'
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security.  The LDAP client configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

Check the ownership of the LDAP configuration file(s).
ls -lL /etc/opt/ldapux/ldapux_client.conf /etc/opt/ldapux/ldapclientd.conf /etc/opt/ldapux/ldapug.conf

If any of the above files are not owned by root or bin, this is a finding.)
  desc 'fix', 'Change the owner of the file.
# chown root <LDAP configuration file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36767r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22560'
  tag rid: 'SV-38384r1_rule'
  tag stig_id: 'GEN008080'
  tag gtitle: 'GEN008080'
  tag fix_id: 'F-32149r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
