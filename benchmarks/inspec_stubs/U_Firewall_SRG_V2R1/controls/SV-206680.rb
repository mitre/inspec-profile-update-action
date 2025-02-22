control 'SV-206680' do
  title 'The firewall must generate traffic log entries containing information to establish the location on the network where the events occurred.'
  desc 'Without establishing where events occurred, it is impossible to establish, correlate, and investigate the events leading up to an outage or attack.

In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as network element components, modules, device identifiers, node names, and functionality. 

Associating information about where the event occurred within the network provides a means of investigating an attack, recognizing resource utilization or capacity thresholds, or identifying an improperly configured network element.'
  desc 'check', "Examine the traffic log configuration on the firewall or view several alert events on the organization's central audit server.

Verify the entries sent to the traffic log include the location of each event (e.g., network name, network subnet, port, or network segment).

If the traffic log entries do not include the event location, this is a finding."
  desc 'fix', 'Configure the firewall to ensure entries sent to the traffic log include the location of each event (e.g., network name, network subnet, network segment, or port).'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6937r297819_chk'
  tag severity: 'medium'
  tag gid: 'V-206680'
  tag rid: 'SV-206680r604133_rule'
  tag stig_id: 'SRG-NET-000076-FW-000011'
  tag gtitle: 'SRG-NET-000076'
  tag fix_id: 'F-6937r297820_fix'
  tag 'documentable'
  tag legacy: ['SV-94145', 'V-79439']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
