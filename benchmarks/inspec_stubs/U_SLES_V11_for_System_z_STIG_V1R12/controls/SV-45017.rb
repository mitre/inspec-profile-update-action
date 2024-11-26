control 'SV-45017' do
  title 'The /etc/group file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.  Additionally, if password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', "Check the /etc/group file for password hashes.
# cut -d : -f 2 /etc/group | egrep -v '^(x|!)$'
If any password hashes are returned, this is a finding."
  desc 'fix', 'Edit /etc/group and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42412r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22348'
  tag rid: 'SV-45017r1_rule'
  tag stig_id: 'GEN001475'
  tag gtitle: 'GEN001475'
  tag fix_id: 'F-38433r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
