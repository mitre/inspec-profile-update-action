control 'SV-226445' do
  title 'UIDs reserved for system accounts must not be assigned to non-system accounts.'
  desc 'Reserved UIDs are typically used by system software packages. If non-system accounts have UIDs in this range, they may conflict with system software, possibly leading to the user having permissions to modify system files.'
  desc 'check', 'Check the UID assignments of all accounts.
# more /etc/passwd

Confirm all accounts with a UID of 99 and below are used by a system account. If a UID reserved for system accounts (0 - 99) is used by a non-system account, this is a finding.'
  desc 'fix', 'Change the UID numbers for non-system accounts with reserved UIDs (those less or equal to 99).'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28606r482702_chk'
  tag severity: 'medium'
  tag gid: 'V-226445'
  tag rid: 'SV-226445r603265_rule'
  tag stig_id: 'GEN000340'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28594r482703_fix'
  tag 'documentable'
  tag legacy: ['V-11946', 'SV-12447']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
