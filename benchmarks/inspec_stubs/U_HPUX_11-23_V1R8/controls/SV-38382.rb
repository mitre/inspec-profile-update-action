control 'SV-38382' do
  title "If the system is using LDAP for authentication or account information, the system must verify the LDAP server's certificate has not been revoked."
  desc 'LDAP can be used to provide user authentication and account information, which are vital to system security. Communication between an LDAP server and a host using LDAP requires authentication.'
  desc 'check', %q(Determine if the system uses LDAP. If it does not, this is not applicable.

# swlist | grep LDAP
OR
# cat /etc/nsswitch.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | grep -i ldap

If no lines are returned for either of the above commands, this vulnerability is not applicable.

Verify the LDAP client is configured to check certificates against a certificate revocation list.
# cat /etc/ldap.conf | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v "^#" | \
grep -i "^tls_crlcheck"

If the setting does not exist, or the value is not all, this is a finding.)
  desc 'fix', 'Edit /etc/ldap.conf and add or set the tls_crlcheck setting to all.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36763r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22558'
  tag rid: 'SV-38382r1_rule'
  tag stig_id: 'GEN008040'
  tag gtitle: 'GEN008040'
  tag fix_id: 'F-32146r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
