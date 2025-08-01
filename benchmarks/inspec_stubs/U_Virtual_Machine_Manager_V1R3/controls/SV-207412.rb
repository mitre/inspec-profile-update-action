control 'SV-207412' do
  title 'All interactions among guest VMs must be mediated by the VMM or its service VMs to support proper function.'
  desc 'Mechanisms to detect and prevent unauthorized communication flow must be configured or provided as part of the VMM design. If information flow control is not enforced based on proper functioning of the VMM and its service, helper, and guest VMs, the VMM may become compromised. Information flow control regulates where information is allowed to travel within a VMM. The flow of all system information must be monitored and controlled so it does not introduce any unacceptable risk to the VMM, its guest VMs, or data.'
  desc 'check', 'Verify all interactions among guest VMs are mediated by the VMM or its service VMs to support proper function.

If they are not, this is a finding.'
  desc 'fix', 'Configure all interactions among guest VMs to be mediated by the VMM or its service VMs to support proper function.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7669r365646_chk'
  tag severity: 'medium'
  tag gid: 'V-207412'
  tag rid: 'SV-207412r379126_rule'
  tag stig_id: 'SRG-OS-000221-VMM-000800'
  tag gtitle: 'SRG-OS-000221'
  tag fix_id: 'F-7669r365647_fix'
  tag 'documentable'
  tag legacy: ['SV-71285', 'V-57025']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
