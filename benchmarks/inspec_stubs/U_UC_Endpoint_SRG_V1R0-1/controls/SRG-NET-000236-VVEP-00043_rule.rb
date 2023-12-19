control 'SRG-NET-000236-VVEP-00043_rule' do
  title 'In the event of a device failure, Unified Communications Endpoints must preserve any information necessary to determine cause of failure and return to operations with least disruption to service.'
  desc 'Failure in a known state can address safety or security in accordance with the mission needs of the organization. Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. Preserving network element state information helps to facilitate network element restart and return to the operational mode of the organization with less disruption to mission-essential processes.'
  desc 'check', 'Verify that in the event of device failure, the Unified Communications Endpoint preserves any information necessary to determine cause of failure and return to operations with least disruption to service.

If the Unified Communications Endpoint does not preserve any information necessary to determine cause of failure, this is a finding. 

If the Unified Communications Endpoint does not return to operations with least disruption to service after device failure, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint, in the event of device failure, to preserve any information necessary to determine cause of failure. Also configure the Unified Communications Endpoint to return to operations with least disruption to service.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000236-VVEP-00043_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000236-VVEP-00043'
  tag rid: 'SRG-NET-000236-VVEP-00043_rule'
  tag stig_id: 'SRG-NET-000236-VVEP-00043'
  tag gtitle: 'SRG-NET-000236-VVEP-00043'
  tag fix_id: 'F-SRG-NET-000236-VVEP-00043_fix'
  tag 'documentable'
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
