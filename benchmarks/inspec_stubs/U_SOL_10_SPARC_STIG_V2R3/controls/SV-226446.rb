control 'SV-226446' do
  title 'GIDs reserved for system accounts must not be assigned to non-system groups.'
  desc 'Reserved GIDs are typically used by system software packages.  If non-system groups have GIDs in this range, they may conflict with system software, possibly leading to the group having permissions to modify system files.'
  desc 'check', '# more /etc/passwd 
Confirm all accounts with a GID of 99 and below are used by a system account. If a GID reserved for system accounts (0 - 99)  is used by a non-system account, this is a finding.'
  desc 'fix', 'Change the primary group GID numbers for non-system accounts with reserved primary group GIDs (those less or equal to 99).

# usermod -g <new_group> <user>'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28607r482705_chk'
  tag severity: 'medium'
  tag gid: 'V-226446'
  tag rid: 'SV-226446r603265_rule'
  tag stig_id: 'GEN000360'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28595r482706_fix'
  tag 'documentable'
  tag legacy: ['V-780', 'SV-28658']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
