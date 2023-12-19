control 'SV-245749' do
  title 'Environmental IA Controls - Training'
  desc 'If employees have not received training on the environmental controls they will not be able to respond to a fluctuation of environmental conditions, which could damage equipment and ultimately disrupt operations.

REFERENCES:

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104   
                               
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AT-3(1)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100, Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check training records to ensure that all required personnel have received their initial and periodic (minimum annually) environmental control training (specifically humidity/temperature). 

Ask personnel how they respond to an environmental alarm.
  
NOTES: This requirement should not be applied to a tactical environment, unless it is a fixed computer facility supporting missions in a Theater of Operations. The standards to be applied for applicability in a tactical environment are:

1) The facility containing the computer room has been in operation for more than one year. 

2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.'
  desc 'fix', '1. All required personnel involved with Information Technology (IT) area/computer rooms must receive initial and periodic (minimum annually) environmental control training (specifically regarding humidity/temperature controls).
 
2. Training records must be updated to reflect this special training.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49180r769907_chk'
  tag severity: 'low'
  tag gid: 'V-245749'
  tag rid: 'SV-245749r769909_rule'
  tag stig_id: 'EC-04.03.01'
  tag gtitle: 'EC-04.03.01'
  tag fix_id: 'F-49135r769908_fix'
  tag 'documentable'
  tag legacy: ['V-30988', 'SV-41032r3_rule']
end
