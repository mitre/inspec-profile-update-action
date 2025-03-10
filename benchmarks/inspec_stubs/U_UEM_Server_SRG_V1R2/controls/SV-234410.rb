control 'SV-234410' do
  title 'In the event of a system failure, the UEM server must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving application state information helps to facilitate application restart and return to the operational mode of the organization with less disruption to mission-essential processes. 

Satisfies:FAU_GEN.1.1(1)'
  desc 'check', 'Verify the UEM server preserves any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes, in the event of a system failure.

If the UEM server does not preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes, in the event of a system failure, this is a finding.'
  desc 'fix', 'Configure the UEM server to preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes, in the event of a system failure.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37595r614240_chk'
  tag severity: 'medium'
  tag gid: 'V-234410'
  tag rid: 'SV-234410r879641_rule'
  tag stig_id: 'SRG-APP-000226-UEM-000137'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-37560r617413_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
