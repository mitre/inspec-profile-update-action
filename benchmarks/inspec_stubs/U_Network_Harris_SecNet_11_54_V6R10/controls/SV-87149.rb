control 'SV-87149' do
  title 'Only supported versions of the Harris SecNet 11/54 should be used.'
  desc 'If an unsupported version of the Harris SecNet wireless router is being used, the device is not being updated with security patches and may contain vulnerabilities that may expose classified data to unauthorized people. The SecNet 11 and 54 support old and obsolete wireless technologies and are no longer being supported by Harris.'
  desc 'check', 'Determine the model numbers of a site’s classified wireless routers. 

If the Harris SecNet 11 or 54 wireless routers are being used, this is a finding.'
  desc 'fix', 'Remove all versions of the Harris SecNet 11 or 54 wireless routers from service and properly dispose of the devices.'
  impact 0.7
  ref 'DPMS Target Harris Secnet 11'
  tag check_id: 'C-72723r1_chk'
  tag severity: 'high'
  tag gid: 'V-72525'
  tag rid: 'SV-87149r1_rule'
  tag stig_id: 'WIR2017'
  tag gtitle: 'WIR2017'
  tag fix_id: 'F-78887r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
