control 'SV-207416' do
  title 'All guest VM network communications must be implemented through use of virtual network devices provisioned by the VMM.'
  desc 'Mechanisms to detect and prevent unauthorized communication flow must be configured or provided as part of the VMM design. If information flow control is not enforced based on proper functioning of the VMM and its service, helper, and guest VMs, the VMM may become compromised. Information flow control regulates where information is allowed to travel between a VMM (and its guest VMs) and external systems. In some cases, the VMM may delegate interface device management to a service VM, but the VMM still maintains control of all information flows. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the VMM, its guest VMs, or data.'
  desc 'check', 'Verify all guest VM network communications are implemented through use of virtual network devices provisioned by the VMM.

If they are not, this is a finding.'
  desc 'fix', 'Configure all guest VM network communications to be implemented through use of virtual network devices provisioned by the VMM.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7673r365658_chk'
  tag severity: 'medium'
  tag gid: 'V-207416'
  tag rid: 'SV-207416r379213_rule'
  tag stig_id: 'SRG-OS-000242-VMM-000840'
  tag gtitle: 'SRG-OS-000242'
  tag fix_id: 'F-7673r365659_fix'
  tag 'documentable'
  tag legacy: ['V-57033', 'SV-71293']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
