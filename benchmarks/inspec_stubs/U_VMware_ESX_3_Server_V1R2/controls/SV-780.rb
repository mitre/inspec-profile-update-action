control 'SV-780' do
  title 'Group Identifiers (GIDs) reserved for system accounts must not be assigned to non-system groups.'
  desc 'Reserved GIDs are typically used by system software packages. If non-system groups have GIDs in this range, they may conflict with system software, possibly leading to the group having permissions to modify system files.'
  desc 'check', '# more /etc/passwd

Confirm all accounts with a GID of 99 and below (499 and below for Linux) are used by a system account.

If a GID reserved for system accounts, 0 - 99 (0 - 499 for Linux), is used by a non-system account, this is a finding.'
  desc 'fix', 'Change the primary group GID numbers for non-system accounts with reserved primary group GIDs (those less or equal to 99 in general, or 499 for Linux).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-280r2_chk'
  tag severity: 'medium'
  tag gid: 'V-780'
  tag rid: 'SV-780r2_rule'
  tag stig_id: 'GEN000360'
  tag gtitle: 'GEN000360'
  tag fix_id: 'F-934r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
