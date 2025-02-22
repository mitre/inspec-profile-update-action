control 'SV-207424' do
  title 'The VMM must limit privileges to change software resident within software libraries.'
  desc 'If the VMM were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to VMMs with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals shall be allowed to obtain access to VMM components for the purpose of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify the VMM limits privileges to change software resident within software libraries.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to limit privileges to change software resident within software libraries.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7681r365682_chk'
  tag severity: 'medium'
  tag gid: 'V-207424'
  tag rid: 'SV-207424r379246_rule'
  tag stig_id: 'SRG-OS-000259-VMM-000930'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-7681r365683_fix'
  tag 'documentable'
  tag legacy: ['SV-71309', 'V-57049']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
