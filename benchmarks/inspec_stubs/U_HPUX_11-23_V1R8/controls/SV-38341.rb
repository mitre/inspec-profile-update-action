control 'SV-38341' do
  title 'The /etc/group file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.  Additionally, if password hashes are readable by non-administrators, the passwords are subject to attack through lookup tables or cryptographic weaknesses in the hashes.'
  desc 'check', 'Check the /etc/group file for password hashes.
# cat /etc/group | cut -f 2,2 -d ":" 

If the above command returns anything other than a blank or "*" character, this is a finding.'
  desc 'fix', 'Edit /etc/group and change the password field to include an asterisk (*) as the first character to lock the group password.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36359r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22348'
  tag rid: 'SV-38341r1_rule'
  tag stig_id: 'GEN001475'
  tag gtitle: 'GEN001475'
  tag fix_id: 'F-31696r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
