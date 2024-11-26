control 'SV-206569' do
  title 'In the event of a system failure, the DBMS must preserve any information necessary to determine cause of failure and any information necessary to return to operations with least disruption to mission processes.'
  desc 'Failure to a known state can address safety or security in accordance with the mission/business needs of the organization.

Failure to a known secure state helps prevent a loss of confidentiality, integrity, or availability in the event of a failure of the information system or a component of the system. 

Preserving information system state information helps to facilitate system restart and return to the operational mode of the organization with less disruption of mission/business processes. 

Since it is usually not possible to test this capability in a production environment, systems should either be validated in a testing environment or prior to installation. This requirement is usually a function of the design of the IDPS component. Compliance can be verified by acceptance/validation processes or vendor attestation.'
  desc 'check', 'Check DBMS settings to determine whether organization-defined system state information is being preserved in the event of a system failure.

If organization-defined system state information is not being preserved, this is a finding.'
  desc 'fix', 'Configure DBMS settings to preserve any organization-defined system state information in the event of a system failure.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6829r291375_chk'
  tag severity: 'medium'
  tag gid: 'V-206569'
  tag rid: 'SV-206569r617447_rule'
  tag stig_id: 'SRG-APP-000226-DB-000147'
  tag gtitle: 'SRG-APP-000226'
  tag fix_id: 'F-6829r291376_fix'
  tag 'documentable'
  tag legacy: ['SV-42866', 'V-32529']
  tag cci: ['CCI-001665']
  tag nist: ['SC-24']
end
