control 'SV-38669' do
  title 'UIDs reserved for system accounts must not be assigned to non-system accounts.'
  desc 'Reserved UIDs are typically used by system software packages. If non-system accounts have UIDs in this range, they may conflict with system software, possibly leading to the user having permissions to modify system files.'
  desc 'check', 'Check the UID assignments of all accounts.

# more /etc/passwd 

Confirm all accounts with a UID of 128 and below are used by a system account. If a UID reserved for system accounts (0-128) is used by a non-system account, this is a finding.'
  desc 'fix', 'Using the usermod command, change the UID numbers for non-system accounts with reserved UIDs (those less or equal to 128).  
# usermod -u <uid> login

Alternatively, smit can be used for this same purpose.   
#smitty users'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36661r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11946'
  tag rid: 'SV-38669r1_rule'
  tag stig_id: 'GEN000340'
  tag gtitle: 'GEN000340'
  tag fix_id: 'F-31625r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
