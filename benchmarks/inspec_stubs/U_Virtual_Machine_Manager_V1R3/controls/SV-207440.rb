control 'SV-207440' do
  title 'The VMM must notify the system administrator and ISSO of account enabling actions.'
  desc 'Once an attacker establishes access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Sending notification of account enabling events to the system administrator and ISSO is one method for mitigating this risk. Such a capability greatly reduces the risk that VMM accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes. 

In order to detect and respond to events that affect user accessibility and application processing, VMMs must audit account enabling actions and, as required, notify the appropriate individuals so they can investigate the event. 

To address access requirements, many VMMs can be integrated with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements.'
  desc 'check', 'Verify the VMM notifies the system administrator and ISSO of account enabling actions.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to notify the system administrator and ISSO of account enabling actions.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7697r365730_chk'
  tag severity: 'medium'
  tag gid: 'V-207440'
  tag rid: 'SV-207440r854613_rule'
  tag stig_id: 'SRG-OS-000304-VMM-001100'
  tag gtitle: 'SRG-OS-000304'
  tag fix_id: 'F-7697r365731_fix'
  tag 'documentable'
  tag legacy: ['V-57081', 'SV-71341']
  tag cci: ['CCI-002132']
  tag nist: ['AC-2 (4)']
end
