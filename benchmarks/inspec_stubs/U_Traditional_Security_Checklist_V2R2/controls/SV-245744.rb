control 'SV-245744' do
  title 'Environmental IA Controls - Emergency Power Shut-Off (EPO)'
  desc 'A lack of an emergency shut-off switch or a master power switch for electricity to IT equipment could cause damage to the equipment or injury to personnel during an emergency.

REFERENCES:

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016 Chapter 5, Section 1, paragraph 5-104 
       
NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls:  PE-10 and PE-10(1)

NIST SP 800-12, An Introduction to Computer Security: The NIST Handbook

NIST SP 800-100 Information Security Handbook: A Guide for Managers'
  desc 'check', 'Check an emergency power cut-off (EPO) switch is located inside the IT room or area near the main entrance/exit. It must be clearly labeled and have a protective cover. This requirement is only for computer centers with large server rooms and/or supporting infrastructure rooms hosting large amounts of network equipment and/or equipment such as chillers, battery backup, transformers, etc. 

NOTES: In general such an area will be in raised floor space. The requirement should not be applied to purely administrative/office space. Also, this requirement should not be applied to a tactical environment, unless it is clearly an "established" fixed computer facility supporting missions in a Theater of Operations. The standards to be applied to determine applicability in a tactical environment are:  
1) The facility containing the computer room has been in operation over 1-year. 
2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc.'
  desc 'fix', '1. A master power switch or emergency cut-off switch for the IT equipment must be located inside the IT area near the main entrance.
 
2. The emergency switch must be properly labeled.
 
3. The emergency switch must be protected by a cover to prevent accidental shut-off of the power.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49175r769892_chk'
  tag severity: 'medium'
  tag gid: 'V-245744'
  tag rid: 'SV-245744r822811_rule'
  tag stig_id: 'EC-01.02.01'
  tag gtitle: 'EC-01.02.01'
  tag fix_id: 'F-49130r769893_fix'
  tag 'documentable'
  tag legacy: ['V-30983', 'SV-41027r3_rule']
end
