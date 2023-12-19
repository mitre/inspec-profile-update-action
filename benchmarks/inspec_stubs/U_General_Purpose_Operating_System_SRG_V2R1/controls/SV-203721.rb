control 'SV-203721' do
  title 'The operating system must prevent program execution in accordance with local policies regarding software program usage and restrictions and/or rules authorizing the terms and conditions of software program usage.'
  desc 'Control of program execution is a mechanism used to prevent execution of unauthorized programs. Some operating systems may provide a capability that runs counter to the mission or provides users with functionality that exceeds mission requirements. This includes functions and services installed at the operating system-level.

Some of the programs, installed by default, may be harmful or may not be necessary to support essential organizational operations (e.g., key missions, functions). Removal of executable programs is not always possible; therefore, establishing a method of preventing program execution is critical to maintaining a secure system baseline.

Methods for complying with this requirement include restricting execution of programs in certain environments, while preventing execution in other environments; or limiting execution of certain program functionality based on organization-defined criteria (e.g., privileges, subnets, sandboxed environments, or roles).'
  desc 'check', 'Verify the operating system prevents program execution in accordance with local policies regarding software program usage and restrictions and/or rules authorizing the terms and conditions of software program usage. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to prevent program execution in accordance with local policies regarding software program usage and restrictions and/or rules authorizing the terms and conditions of software program usage.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3846r375170_chk'
  tag severity: 'medium'
  tag gid: 'V-203721'
  tag rid: 'SV-203721r379831_rule'
  tag stig_id: 'SRG-OS-000368-GPOS-00154'
  tag gtitle: 'SRG-OS-000368'
  tag fix_id: 'F-3846r375171_fix'
  tag 'documentable'
  tag legacy: ['V-56845', 'SV-71105']
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
end
