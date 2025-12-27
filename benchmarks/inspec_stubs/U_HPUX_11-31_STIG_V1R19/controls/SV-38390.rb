control 'SV-38390' do
  title 'For systems using NSS LDAP, the TLS certificate file must be owned by root.'
  desc 'The NSS LDAP service provides user mappings which are a vital component of system security.  Its configuration must be protected from unauthorized modification.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable. 
# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If nothing is returned for either of the above commands, this is not applicable.

If LDAP is installed, check the ownership of the LDAP cert file(s).
# ls -lLa /etc/opt/ldapux/cert8.db

If the owner of the file is not root or bin, this is a finding.)
  desc 'fix', 'Change the ownership of the file.
# chown root <certfile>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36775r1_chk'
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
