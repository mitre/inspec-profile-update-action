control 'SV-7004' do
  title 'The MFD or Network Printer must maintain configuration state (e.g., passwords, service settings) after a power down or restart.'
  desc 'If the MFD does not maintain it state over a power down or restart, it will expose the network to all of the vulnerabilities that where mitigated by the modifications made to its configuration state. This also prevents accidental implementation of a “call-home” feature that is not allowed.'
  desc 'check', 'The reviewer will verify the MFD or Network Printer maintains its configuration state after a power down or restart. Review the device documentation and/or confirm through demonstration to verify the MFD maintains configuration settings.

If the MFD or Network Printer does not maintain its configuration state, this is a finding.'
  desc 'fix', 'If the MFD or Network Printer cannot be configured to maintain state, then replace the MFD with a MFD that will maintain its configuration state (passwords, service settings, etc) after a power down or restart.'
  impact 0.7
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2968r2_chk'
  tag severity: 'high'
  tag gid: 'V-6782'
  tag rid: 'SV-7004r2_rule'
  tag stig_id: 'MFD02.002'
  tag gtitle: 'MFD Configuration State After Power Down or Reboot'
  tag fix_id: 'F-6435r2_fix'
  tag 'documentable'
end
