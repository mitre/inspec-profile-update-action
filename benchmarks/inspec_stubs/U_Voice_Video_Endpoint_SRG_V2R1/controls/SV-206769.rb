control 'SV-206769' do
  title 'In the event of a device failure, hardware Voice Video Endpoints must preserve any information necessary to determine cause of failure and return to operations with least disruption to service.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving network element state information helps to facilitate network element restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify that in the event of device failure, the hardware Voice Video Endpoint preserves any information necessary to determine cause of failure and return to operations with least disruption to service.

If the hardware Voice Video Endpoint does not preserve any information necessary to determine cause of failure, this is a finding. 

If the hardware Voice Video Endpoint does not return to operations with least disruption to service after device failure, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint, in the event of device failure, to preserve any information necessary to determine cause of failure. Also configure the hardware Voice Video Endpoint to return to operations with least disruption to service.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7025r363830_chk'
  tag severity: 'medium'
  tag gid: 'V-206769'
  tag rid: 'SV-206769r604140_rule'
  tag stig_id: 'SRG-NET-000236-VVEP-00043'
  tag gtitle: 'SRG-NET-000236'
  tag fix_id: 'F-7025r363831_fix'
  tag 'documentable'
  tag legacy: ['SV-81257', 'V-66767']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
