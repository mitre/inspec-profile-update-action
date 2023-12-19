control 'SV-245747' do
  title 'Environmental IA Controls - Voltage Control (power)'
  desc 'Failure to use automatic voltage control can result in damage to the IT equipment creating a service outage.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104     
                             
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-9(2)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100 Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check there is an IT area voltage control unit and that it is being utilized for all key IT assets.
   
NOTES: This requirement should not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations. The standards to be applied for applicability in a tactical environment are:

1) The facility containing the computer room has been in operation over one year. 
2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.'
  desc 'fix', 'An Information Technology (IT) area voltage control unit must be installed and used for all key IT assets.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49178r769901_chk'
  tag severity: 'low'
  tag gid: 'V-245747'
  tag rid: 'SV-245747r769903_rule'
  tag stig_id: 'EC-03.03.01'
  tag gtitle: 'EC-03.03.01'
  tag fix_id: 'F-49133r769902_fix'
  tag 'documentable'
  tag legacy: ['V-30987', 'SV-41031r3_rule']
end
