control 'SV-218209' do
  title 'UIDs reserved for system accounts must not be assigned to non-system accounts.'
  desc 'Reserved UIDs are typically used by system software packages.  If non-system accounts have UIDs in this range, they may conflict with system software, possibly leading to the user having permissions to modify system files.'
  desc 'check', 'Check the UID assignments for all accounts.

# cut -d: -f 1,3 /etc/passwd | egrep ":[1-4][0-9]{2}$|:[0-9]{1,2}$"

Confirm all accounts with a UID of 499 and below are used by a system account. If a UID reserved for system accounts (0 - 499) is used by a non-system account, then this is a finding.'
  desc 'fix', 'Change the UID numbers for non-system accounts with reserved UIDs (those less or equal to 499).'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19684r553964_chk'
  tag severity: 'medium'
  tag gid: 'V-218209'
  tag rid: 'SV-218209r603259_rule'
  tag stig_id: 'GEN000340'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19682r553965_fix'
  tag 'documentable'
  tag legacy: ['V-11946', 'SV-63277']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
