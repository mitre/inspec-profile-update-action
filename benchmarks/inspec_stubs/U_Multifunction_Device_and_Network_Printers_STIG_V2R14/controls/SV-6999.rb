control 'SV-6999' do
  title 'The MFD or Network Printer must not enable network protocols other than TCP/IP.'
  desc 'The greater the number of protocols allowed active on the network the more vulnerabilities there will be available to be exploited. This also prevents accidental implementation of a “call-home” feature that is not allowed.'
  desc 'check', 'The reviewer will verify the configuration settings in the MFD or Network Printer to ensure the only protocol enabled is TCP/IP.

If a protocol other than TCP/IP is enabled, this is a finding.'
  desc 'fix', 'Configure the MFD or Network Printer to disable all protocols except TCP/IP.'
  impact 0.5
  ref 'DPMS Target Multifunction Device - MFD'
  tag check_id: 'C-2941r2_chk'
  tag severity: 'medium'
  tag gid: 'V-6777'
  tag rid: 'SV-6999r2_rule'
  tag stig_id: 'MFD01.001'
  tag gtitle: 'MFD Protocol TCP/IP'
  tag fix_id: 'F-6430r2_fix'
  tag 'documentable'
end
