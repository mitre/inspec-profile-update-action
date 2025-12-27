control 'SV-207417' do
  title 'All interactions between guest VMs and external systems, via other interface devices, must be mediated by the VMM or its service VMs.'
  desc 'Mechanisms to detect and prevent unauthorized communication flow must be configured or provided as part of the VMM design. If information flow control is not enforced based on proper functioning of the VMM and its service and helper VMs, the VMM may become compromised. Information flow control regulates where information is allowed to travel between a VMM (and its guest VMs) and external systems. In some cases, the VMM may delegate interface device management to a service VM, but the VMM still maintains control of all information flows. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the VMM, its guest VMs, or data.'
  desc 'check', 'Verify all interactions between guest VMs and external systems, via other interface devices, are mediated by the VMM or its service VMs.

If they are not, this is a finding.'
  desc 'fix', 'Configure all interactions between guest VMs and external systems, via other interface devices, are mediated by the VMM or its service VMs.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7674r365661_chk'
  tag severity: 'medium'
  tag gid: 'V-207417'
  tag rid: 'SV-207417r379213_rule'
  tag stig_id: 'SRG-OS-000242-VMM-000850'
  tag gtitle: 'SRG-OS-000242'
  tag fix_id: 'F-7674r365662_fix'
  tag 'documentable'
  tag legacy: ['V-57035', 'SV-71295']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
