control 'SV-229010' do
  title 'The BIG-IP appliance must be configured to use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and IAW with CJCSM 6510.01B.'
  desc 'By immediately displaying an alarm message, potential security violations can be identified more quickly even when administrators are not logged onto the network device. An example of a mechanism to facilitate this would be through the utilization of SNMP traps.'
  desc 'check', 'Verify the BIG-IP appliance is configured to use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and IAW with CJCSM 6510.01B. 

Navigate to the BIG-IP System manager >> System >> Logs >> Configuration >> Log Destinations.

Verify a log destination is configured for a CNDSP or other mechanism that is monitored by security personnel.

If the BIG-IP appliance is not configured to use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and IAW with CJCSM 6510.01B, this is a finding.'
  desc 'fix', 'Configure the BIG-IP appliance to use automated mechanisms to alert security personnel to threats identified by authoritative sources (e.g., CTOs) and IAW with CJCSM 6510.01B.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Device Management 11.x'
  tag check_id: 'C-31325r518074_chk'
  tag severity: 'medium'
  tag gid: 'V-229010'
  tag rid: 'SV-229010r557520_rule'
  tag stig_id: 'F5BI-DM-000263'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-31302r518075_fix'
  tag 'documentable'
  tag legacy: ['V-60225', 'SV-74655']
  tag cci: ['CCI-000366', 'CCI-001274']
  tag nist: ['CM-6 b', 'SI-4 (12)']
end
