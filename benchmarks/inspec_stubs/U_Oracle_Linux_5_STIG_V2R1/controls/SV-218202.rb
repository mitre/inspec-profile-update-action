control 'SV-218202' do
  title 'The system must not have unnecessary accounts.'
  desc 'Accounts providing no operational purpose provide additional opportunities for system compromise.  Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.'
  desc 'check', 'Check the system for unnecessary user accounts. 

Procedure:

# more /etc/passwd 

Obtain a list of authorized accounts from the IAO.  If any unnecessary accounts are found on the system, this is a finding.'
  desc 'fix', 'Remove all unnecessary accounts from the /etc/passwd file before connecting a system to the network. Other accounts that are associated with a service not in use should also be removed.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19677r568540_chk'
  tag severity: 'medium'
  tag gid: 'V-218202'
  tag rid: 'SV-218202r603259_rule'
  tag stig_id: 'GEN000290'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19675r568541_fix'
  tag 'documentable'
  tag legacy: ['V-4269', 'SV-63195']
  tag cci: ['CCI-000012', 'CCI-000366']
  tag nist: ['AC-2 j', 'CM-6 b']
end
