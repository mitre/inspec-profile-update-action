control 'SV-216201' do
  title 'The root account must be the only account with GID of 0.'
  desc 'All accounts with a GID of 0 have root group privileges and must be limited to the group account only.'
  desc 'check', "Identify any users with GID of 0.

# awk -F: '$4 == 0' /etc/passwd
# awk -F: '$3 == 0' /etc/group
Confirm the only account with a group id of 0 is root.

If the root account is not the only account with GID of 0, this is a finding."
  desc 'fix', 'The root role is required.

Change the default GID of non-root accounts to a valid GID other than 0.'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17439r372985_chk'
  tag severity: 'medium'
  tag gid: 'V-216201'
  tag rid: 'SV-216201r603268_rule'
  tag stig_id: 'SOL-11.1-070220'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17437r372986_fix'
  tag 'documentable'
  tag legacy: ['V-48035', 'SV-60907']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
