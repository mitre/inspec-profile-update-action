control 'SV-4582' do
  title 'The network device must require authentication for console access.'
  desc 'Network devices with no password for administrative access via the console provide the opportunity for anyone with physical access to the device to make configuration changes enabling them to disrupt network operations resulting in a network outage.'
  desc 'check', "Review the network device's configuration and verify authentication is required for console access.

If authentication is not configured for console access, this is a finding."
  desc 'fix', 'Configure authentication for console access on the network device.'
  impact 0.7
  ref 'DPMS Target WLAN Bridge'
  tag check_id: 'C-3510r6_chk'
  tag severity: 'high'
  tag gid: 'V-4582'
  tag rid: 'SV-4582r5_rule'
  tag stig_id: 'NET1623'
  tag gtitle: 'Authentication required for console access.'
  tag fix_id: 'F-4515r4_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
