control 'SV-222636' do
  title 'A disaster recovery/continuity plan must exist in accordance with DoD policy based on the applications availability requirements.'
  desc 'All applications must document disaster recovery/continuity  procedures to include business recovery plans, system contingency plans, facility disaster recovery plans, and plan acceptance.'
  desc 'check', 'Review disaster recovery/continuity plans.

For high risk applications, verify the disaster plan exists and provides for the smooth transfer of all mission or business essential functions to an alternate site for the duration of an event with little or no loss of operational continuity.
 
For moderate risk applications, verify the disaster recovery/continuity plan exists and provides for the resumption of mission or business essential functions within 24 hours activation.

For low risk applications, verify the disaster recovery/continuity plan exists and provides for the partial resumption of mission or business essential functions within 5 days of activation.
 
If the disaster recovery/continuity plan does not exist or does not meet the severity level requirements, this is a finding.'
  desc 'fix', 'Create and maintain the disaster recovery/continuity plan.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24306r493816_chk'
  tag severity: 'medium'
  tag gid: 'V-222636'
  tag rid: 'SV-222636r879887_rule'
  tag stig_id: 'APSC-DV-003050'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24295r493817_fix'
  tag 'documentable'
  tag legacy: ['SV-84973', 'V-70351']
  tag cci: ['CCI-000445']
  tag nist: ['CP-2 a 1']
end
