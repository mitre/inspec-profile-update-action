control 'SV-218307' do
  title 'The /etc/group file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.  Additionally, if password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', "Check the /etc/group file for password hashes.

# cut -d : -f 2 /etc/group | egrep -v '^(x|!)$'

If any password hashes are returned, this is a finding."
  desc 'fix', 'Edit /etc/group and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19782r554258_chk'
  tag severity: 'medium'
  tag gid: 'V-218307'
  tag rid: 'SV-218307r603259_rule'
  tag stig_id: 'GEN001475'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19780r554259_fix'
  tag 'documentable'
  tag legacy: ['V-22348', 'SV-64583']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
