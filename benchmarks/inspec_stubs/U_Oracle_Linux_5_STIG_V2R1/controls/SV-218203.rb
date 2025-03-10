control 'SV-218203' do
  title 'The system must not have the unnecessary games account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for the unnecessary "games" accounts.

Procedure:
# grep ^games /etc/passwd
If this account exists, it is a finding.'
  desc 'fix', 'Remove the "games" account from the /etc/passwd file before connecting a system to the network.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19678r568543_chk'
  tag severity: 'medium'
  tag gid: 'V-218203'
  tag rid: 'SV-218203r603259_rule'
  tag stig_id: 'GEN000290-1'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19676r568544_fix'
  tag 'documentable'
  tag legacy: ['V-29376', 'SV-63201']
  tag cci: ['CCI-000012', 'CCI-000366']
  tag nist: ['AC-2 j', 'CM-6 b']
end
