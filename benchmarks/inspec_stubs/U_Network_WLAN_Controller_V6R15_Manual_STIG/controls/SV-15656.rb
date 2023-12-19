control 'SV-15656' do
  title 'The WLAN inactive session timeout must be set for 30 minutes or less.'
  desc 'A WLAN session that never terminates due to inactivity may allow an opening for an adversary to highjack the session to obtain access to the network.'
  desc 'check', '1. Review the relevant configuration screen of the WLAN controller or access point.   
2. Verify the session timeout setting is set for 30 minutes or less. 
4. Mark as a finding if any of the following are found.
- Session timeout is not set to 30 minutes or less for the entire WLAN.
- The WLAN does not have the capability to enable the session time-out feature.'
  desc 'fix', 'Set the WLAN inactive session timeout to 30 minutes or less.'
  impact 0.5
  ref 'DPMS Target WLAN Controller'
  tag check_id: 'C-13416r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14888'
  tag rid: 'SV-15656r1_rule'
  tag stig_id: 'WIR0110'
  tag gtitle: 'WLAN session timeout set to 30 minutes or less'
  tag fix_id: 'F-34136r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
