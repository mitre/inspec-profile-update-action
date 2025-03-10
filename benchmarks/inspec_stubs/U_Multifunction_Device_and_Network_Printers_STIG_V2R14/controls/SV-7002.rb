control 'SV-7002' do
  title 'The MFD or Network Printer must employ the most current firmware available.'
  desc 'MFD devices or printers utilizing old firmware can expose the network to known vulnerabilities leading to a denial of service or a compromise of sensitive data. While the MFD must use the most current firmware available, it must not use a “call-home” feature that is not allowed.'
  desc 'check', 'The reviewer will verify that the MFD or Network Printer are flash upgradeable and are configured to use the most current firmware available. 

Ensure any “call-home” feature is disabled.

If the MFD or Network Printer is not flash upgradeable, this is a finding.

If the MFD or Network Printer is not configured with the most current firmware, this is a finding.

If the MFD or Network Printer has the “call-home” feature enabled, this is a finding.'
  desc 'fix', 'If the MFD or printer cannot be upgraded replace it.

If the MFD or printer can be upgraded but is not using the latest release of the firmware, upgrade the firmware.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2965r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6780'
  tag rid: 'SV-7002r2_rule'
  tag stig_id: 'MFD02.004'
  tag gtitle: 'MFD Firmware'
  tag fix_id: 'F-6433r2_fix'
  tag 'documentable'
end
