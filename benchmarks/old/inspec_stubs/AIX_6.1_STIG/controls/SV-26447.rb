control 'SV-26447' do
  title 'The /etc/group file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.  Additionally, if password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', "Check the /etc/group file for password hashes.
Procedure:
# cut -d : -f 2 /etc/group | egrep -v '^(x|!)$'
If any password hashes are returned, this is a finding.
If no password hashes are returned, there is no finding."
  desc 'fix', 'Edit /etc/group and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-27519r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22348'
  tag rid: 'SV-26447r1_rule'
  tag stig_id: 'GEN001475'
  tag gtitle: 'GEN001475'
  tag fix_id: 'F-23639r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
