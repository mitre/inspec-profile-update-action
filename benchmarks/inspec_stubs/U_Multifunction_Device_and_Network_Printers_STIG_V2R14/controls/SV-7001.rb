control 'SV-7001' do
  title 'A firewall or router rule must block all ingress and egress traffic from the enclave perimeter to the MFD or Network Printer.'
  desc 'Access to the MFD or printer from outside the enclave network could lead to a denial of service caused by a large number of large print files being sent to the device. Ability for the MFD or printer to access addresses outside the enclave network could lead to a compromise of sensitive data caused by forwarding a print file to a location outside of the enclave network. This also prevents accidental implementation of a “call-home” feature that is not allowed.'
  desc 'check', 'The reviewer will verify that a firewall or router rule blocks all ingress and egress traffic from the enclave perimeter to the MFD or Network Printer.

If a firewall or router does not block all ingress and egress traffic from the enclave perimeter to the MFD or Network Printer, this is a finding.'
  desc 'fix', 'Configure a firewall or router rule to block all ingress and egress traffic from the enclave perimeter to the MFD or Network Printer.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2954r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6779'
  tag rid: 'SV-7001r2_rule'
  tag stig_id: 'MFD01.003'
  tag gtitle: 'MFD/Printer Firewall/Router Rule Perimeter'
  tag fix_id: 'F-6432r2_fix'
  tag 'documentable'
end
