control 'SV-38454' do
  title 'GIDs reserved for system accounts must not be assigned to non-system groups.'
  desc 'Reserved GIDs are typically used by system software packages. If non-system groups have GIDs in this range, they may conflict with system software, possibly leading to the group having permissions to modify system files.'
  desc 'check', 'Confirm all accounts with a GID of 99 and below are used by a system account. If a GID reserved for system accounts (0 - 99) is used by a non-system account, this is a finding. The vendor-supplied system default group "users" (gid=20) is considered an exception to this check.

# cat /etc/passwd | cut -f 1,4 -d ":"'
  desc 'fix', 'Change the primary group GID numbers for non-system accounts with reserved primary group GIDs (those less or equal to 99).

# usermod -g <new_group> <user>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36253r3_chk'
  tag severity: 'medium'
  tag gid: 'V-780'
  tag rid: 'SV-38454r1_rule'
  tag stig_id: 'GEN000360'
  tag gtitle: 'GEN000360'
  tag fix_id: 'F-31510r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
