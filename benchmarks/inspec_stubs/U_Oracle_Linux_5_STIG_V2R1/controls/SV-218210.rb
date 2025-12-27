control 'SV-218210' do
  title 'GIDs reserved for system accounts must not be assigned to non-system groups.'
  desc 'Reserved GIDs are typically used by system software packages.  If non-system groups have GIDs in this range, they may conflict with system software, possibly leading to the group having permissions to modify system files.'
  desc 'check', 'Confirm all accounts with a GID of 499 and below are used by a system account. 

Procedure:
List all the users with a GID of 0-499.
# cut -d: -f 1,4 /etc/passwd|egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"

If a GID reserved for system accounts (0 - 499) is used by a non-system account, this is a finding.'
  desc 'fix', 'Change the primary group GID numbers for non-system accounts with reserved primary group GIDs (those less or equal to 499).'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19685r553967_chk'
  tag severity: 'medium'
  tag gid: 'V-218210'
  tag rid: 'SV-218210r603259_rule'
  tag stig_id: 'GEN000360'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19683r553968_fix'
  tag 'documentable'
  tag legacy: ['V-780', 'SV-63299']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
