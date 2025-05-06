control 'SV-242599' do
  title 'The Cisco ISE must perform continuous detection and tracking of endpoint devices attached to the network.'
  desc "Continuous scanning capabilities on the Cisco ISE provide visibility of devices that are connected to the switch ports. The Cisco ISE continuously scans networks and monitors the activity of managed and unmanaged devices, which can be personally owned or rogue endpoints. Because many of today's small devices do not include agents, an agentless discovery is often combined to cover more types of equipment."
  desc 'check', 'Review the posture settings to ensure Continuous Monitoring Interval is enabled and a value configured. 

From the Web Admin portal:
1. Choose Work Centers >> Posture >> Settings >> Posture General Settings.
2. Verify that "Continuous Monitoring Interval" is enabled and an interval configured. 

If "Continuous Monitoring Interval" is not enabled with an interval defined, this is a finding.'
  desc 'fix', 'Configure the posture settings to enable Continuous Monitoring Interval. 

From the Web Admin portal:
1. Choose Work Centers >> Posture >> Settings >> Posture General Settings.
2. Check "Continuous Monitoring Interval" and define an interval to enable continuous monitoring.
3. Choose "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NAC'
  tag check_id: 'C-45874r714105_chk'
  tag severity: 'medium'
  tag gid: 'V-242599'
  tag rid: 'SV-242599r714107_rule'
  tag stig_id: 'CSCO-NC-000250'
  tag gtitle: 'SRG-NET-000512-NAC-002310'
  tag fix_id: 'F-45831r714106_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
