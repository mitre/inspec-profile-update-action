control 'SV-245746' do
  title 'Environmental IA Controls  - Emergency Lighting and Exits - Documentation and Testing'
  desc 'Lack of automatic emergency lighting can cause injury and/or death to employees and emergency responders. Lack of automatic emergency lighting can cause a disruption in service.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104   
   
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-1, PE-12 and PE-12(1)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100 Information Security Handbook: A Guide for Managers'
  desc 'check', 'Review Emergency Lighting and Exit documentation and testing. Check to ensure:

1. There are written procedures for emergency exit.

2. Evacuation routes are posted within the facility for employee reference.

3. The plan is rehearsed on a periodic basis.
 
4. Emergency lighting is tested on a periodic basis.
 
NOTES: This requirement should not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations. The considerations to be applied for applicability in a tactical environment are:  

1) The facility containing the computer room has been in operation over one year. 
2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.'
  desc 'fix', 'Emergency Lighting and Exit documentation and testing.
 
1. There must be written procedures for emergency exit.

2. Evacuation routes must be posted in the facility for employee reference.
 
3. The emergency exit plan must be rehearsed on a periodic basis.
 
4. Emergency lighting must be tested on a periodic basis.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49177r769898_chk'
  tag severity: 'low'
  tag gid: 'V-245746'
  tag rid: 'SV-245746r769900_rule'
  tag stig_id: 'EC-02.03.01'
  tag gtitle: 'EC-02.03.01'
  tag fix_id: 'F-49132r769899_fix'
  tag 'documentable'
  tag legacy: ['V-30985', 'SV-41029r3_rule']
end
