control 'SV-227572' do
  title 'GIDs reserved for system accounts must not be assigned to non-system groups.'
  desc 'Reserved GIDs are typically used by system software packages.  If non-system groups have GIDs in this range, they may conflict with system software, possibly leading to the group having permissions to modify system files.'
  desc 'check', '# more /etc/passwd 
Confirm all accounts with a GID of 99 and below are used by a system account. If a GID reserved for system accounts (0 - 99)  is used by a non-system account, this is a finding.'
  desc 'fix', 'Change the primary group GID numbers for non-system accounts with reserved primary group GIDs (those less or equal to 99).

# usermod -g <new_group> <user>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29734r488255_chk'
  tag severity: 'medium'
  tag gid: 'V-227572'
  tag rid: 'SV-227572r603266_rule'
  tag stig_id: 'GEN000360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29722r488256_fix'
  tag 'documentable'
  tag legacy: ['V-780', 'SV-28658']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
