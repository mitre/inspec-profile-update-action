control 'SV-218167' do
  title 'The /etc/gshadow file must not contain any group password hashes.'
  desc 'Group passwords are typically shared and should not be used.'
  desc 'check', "Check the /etc/gshadow file for password hashes.
# cut -d : -f 2 /etc/gshadow | egrep -v '^(x|!!)$'
If any password hashes are returned, this is a finding."
  desc 'fix', 'Edit /etc/gshadow and change the password field to an exclamation point (!) to lock the group password.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19642r553838_chk'
  tag severity: 'medium'
  tag gid: 'V-218167'
  tag rid: 'SV-218167r603259_rule'
  tag stig_id: 'GEN000000-LNX001476'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19640r553839_fix'
  tag 'documentable'
  tag legacy: ['V-22349', 'SV-62767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
