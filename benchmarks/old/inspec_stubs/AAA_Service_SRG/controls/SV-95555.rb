control 'SV-95555' do
  title 'AAA Services must be configured to automatically audit account enabling actions.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Automatically auditing account enabling actions provides logging that can be used for forensic purposes.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function. 

Verify AAA Services are configured to automatically audit account enabling actions.

If AAA Services are not configured to automatically audit account enabling actions, this is a finding.'
  desc 'fix', 'Configure AAA Services to automatically audit account enabling actions.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80581r3_chk'
  tag severity: 'medium'
  tag gid: 'V-80845'
  tag rid: 'SV-95555r1_rule'
  tag stig_id: 'SRG-APP-000319-AAA-000170'
  tag gtitle: 'SRG-APP-000319-AAA-000170'
  tag fix_id: 'F-87699r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
