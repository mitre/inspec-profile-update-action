control 'SV-207403' do
  title 'The VMM must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to the VMM. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular VMM components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific VMM components.'
  desc 'check', 'Verify the VMM prevents unauthorized and unintended information transfer via shared system resources.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to prevent unauthorized and unintended information transfer via shared system resources.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7660r365619_chk'
  tag severity: 'medium'
  tag gid: 'V-207403'
  tag rid: 'SV-207403r378982_rule'
  tag stig_id: 'SRG-OS-000138-VMM-000670'
  tag gtitle: 'SRG-OS-000138'
  tag fix_id: 'F-7660r365620_fix'
  tag 'documentable'
  tag legacy: ['SV-71267', 'V-57007']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
