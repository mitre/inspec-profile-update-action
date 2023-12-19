control 'SV-203675' do
  title 'The operating system must limit privileges to change software resident within software libraries.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify the operating system limits privileges to change software resident within software libraries. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to limit privileges to change software resident within software libraries.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3800r374912_chk'
  tag severity: 'medium'
  tag gid: 'V-203675'
  tag rid: 'SV-203675r379246_rule'
  tag stig_id: 'SRG-OS-000259-GPOS-00100'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-3800r374913_fix'
  tag 'documentable'
  tag legacy: ['V-57183', 'SV-71443']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
