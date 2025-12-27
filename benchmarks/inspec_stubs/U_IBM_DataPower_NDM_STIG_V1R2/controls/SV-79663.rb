control 'SV-79663' do
  title 'The DataPower Gateway must use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and in accordance with CJCSM 6510.01B.'
  desc 'By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged into the network device. An example of a mechanism to facilitate this would be through the utilization of SNMP traps.'
  desc 'check', 'Go to Administration >> Access >> SNMP Settings. Verify the IP address, port, and security settings. Go to the Trap and Notification Targets tab. Verify the remote server/receiver information. If these values have not been set, this is a finding.'
  desc 'fix', 'Go to Administration >> Access >> SNMP Settings. Configure the IP address, port, and security settings. 

Go to the Trap and Notification Targets tab. Enter the remote server/receiver information.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65173'
  tag rid: 'SV-79663r1_rule'
  tag stig_id: 'WSDP-NM-000131'
  tag gtitle: 'SRG-APP-000516-NDM-000333'
  tag fix_id: 'F-71113r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001274']
  tag nist: ['CM-6 b', 'SI-4 (12)']
end
