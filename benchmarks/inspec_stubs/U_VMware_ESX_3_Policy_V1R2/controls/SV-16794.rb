control 'SV-16794' do
  title 'Disaster recovery plan does not include ESX Servers, VirtualCenter servers, virtual machines, and necessary peripherals associated with the system.'
  desc 'Disaster and recovery plans should be drafted and exercised in accordance with the MAC level of the system/Enclave as defined by the DoDI 85002. Disaster plans provide for the resumption of mission or business essential functions. A disaster plan must exist that provides for the resumption of mission or business essential functions within the specified period of time depending on MAC level. (Disaster recovery procedures include business recovery plans, system contingency plans, facility disaster recovery plans, and plan acceptance).'
  desc 'check', 'Request a copy of the disaster recovery plan from the IAO/SA.  Review the plan to verify that the ESX Server, management applications, virtual machines, and all necessary system peripherals are included in the plan.  If the plan does not include the virtual infrastructure or is incomplete, this is a finding.'
  desc 'fix', 'Add the virtual infrastructure to the disaster recovery plan.'
  impact 0.5
  ref 'DPMS Target ESX Architecture and Policy'
  tag check_id: 'C-16202r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15853'
  tag rid: 'SV-16794r1_rule'
  tag stig_id: 'ESX0540'
  tag gtitle: 'Disaster recovery plan is not complete'
  tag fix_id: 'F-15807r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'CODP-1, CODP-2, CODP-3'
end
