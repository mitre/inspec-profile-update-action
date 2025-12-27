control 'SV-3175' do
  title 'The network device must require authentication prior to establishing a management connection for administrative access.'
  desc 'Network devices with no password for administrative access via a management connection provide the opportunity for anyone with network access to the device to make configuration changes enabling them to disrupt network operations resulting in a network outage.'
  desc 'check', "Review the network device configuration to verify all management connections for administrative access require authentication.

If authentication isn't configured for management access, this is a finding."
  desc 'fix', 'Configure authentication for all management connections.'
  impact 0.7
  ref 'DPMS Target WLAN Bridge'
  tag check_id: 'C-3516r9_chk'
  tag severity: 'high'
  tag gid: 'V-3175'
  tag rid: 'SV-3175r5_rule'
  tag stig_id: 'NET1636'
  tag gtitle: 'Management connections must require passwords.'
  tag fix_id: 'F-3200r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
