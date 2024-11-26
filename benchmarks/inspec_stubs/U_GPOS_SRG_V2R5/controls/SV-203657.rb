control 'SV-203657' do
  title 'Operating systems must prevent unauthorized and unintended information transfer via shared system resources.'
  desc 'Preventing unauthorized information transfers mitigates the risk of information, including encrypted representations of information, produced by the actions of prior users/roles (or the actions of processes acting on behalf of prior users/roles) from being available to any current users/roles (or current processes) that obtain access to shared system resources (e.g., registers, main memory, hard disks) after those resources have been released back to information systems. The control of information in shared resources is also commonly referred to as object reuse and residual information protection.

This requirement generally applies to the design of an information technology product, but it can also apply to the configuration of particular information system components that are, or use, such products. This can be verified by acceptance/validation processes in DoD or other government agencies.

There may be shared resources with configurable protections (e.g., files in storage) that may be assessed on specific information system components.'
  desc 'check', 'Verify operating systems prevents unauthorized and unintended information transfer via shared system resources. If it does not, this is a finding.'
  desc 'fix', 'Configure operating systems to prevent unauthorized and unintended information transfer via shared system resources.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3782r557216_chk'
  tag severity: 'medium'
  tag gid: 'V-203657'
  tag rid: 'SV-203657r557218_rule'
  tag stig_id: 'SRG-OS-000138-GPOS-00069'
  tag gtitle: 'SRG-OS-000138'
  tag fix_id: 'F-3782r557217_fix'
  tag 'documentable'
  tag legacy: ['V-56853', 'SV-71113']
  tag cci: ['CCI-001090']
  tag nist: ['SC-4']
end
