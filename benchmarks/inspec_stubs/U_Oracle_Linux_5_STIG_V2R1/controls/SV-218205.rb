control 'SV-218205' do
  title 'The system must not have the unnecessary gopher account.'
  desc 'Accounts that provide no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for the unnecessary "gopher" accounts.

Procedure:
# grep ^gopher /etc/passwd
If this account exists, it is a finding.'
  desc 'fix', 'Remove the "gopher" account from the /etc/passwd file before connecting a system to the network.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19680r568549_chk'
  tag severity: 'medium'
  tag gid: 'V-218205'
  tag rid: 'SV-218205r603259_rule'
  tag stig_id: 'GEN000290-3'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19678r568550_fix'
  tag 'documentable'
  tag legacy: ['V-27276', 'SV-63227']
  tag cci: ['CCI-000012', 'CCI-000366']
  tag nist: ['AC-2 j', 'CM-6 b']
end
