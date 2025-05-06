control 'SV-245839' do
  title 'Destruction of Classified and Unclassified Documents, Equipment and Media - Availability of Local Policy and Procedures'
  desc 'Lack of plans and procedures to properly destroy classified and/or sensitive material can lead to the loss or compromise of classified or sensitive information.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraphs 21.h.(9); 28; 29b.,d.(1)(2).h.(1)(2) and para 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: MP-1, MP-6, PE-1.

DODI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 9.b.(8) (9) 

DOD Manual 5200.01, Volume 3, SUBJECT: DOD Information Security Program: Protection of Classified Information: Enclosure 2, paragraph 14 14(d); Enclosure 3 paragraphs 17, 18, 19; Enclosure 5, paragraph 3.d.(3); Enclosure 7, paragraph 6.

Assistant Secretary of Defense for Command, Control, Communications and Intelligence Memorandum, Disposition of Unclassified DOD Computer Hard Drives, June 4, 2001

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, paragraphs 5-704, 5-705, 5-706, 5-707, 5-708, 8-202.e. & 8-302.g.

NIST SP 800-88, Guidelines for Media Sanitization

NSA/CSA Policy Manual 9-12, NSA/CSS Storage Device Declassification Manual

https://www.nsa.gov/Resources/Media-Destruction-Guidance

'
  desc 'check', 'Check to ensure there are procedures for the destruction of classified or sensitive documents, systems and media. Also check to ensure this documentation is readily available for employee reference and included in initial and recurring (annual) security training.  

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments where procedural documents (SOPs) should be in place. Not applicable to a field/mobile environment.'
  desc 'fix', 'Ensure there are procedures for the destruction of classified or sensitive documents, systems and media. Also check to ensure this documentation is readily available for employee reference and included in initial and recurring (annual) security training.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49270r917241_chk'
  tag severity: 'low'
  tag gid: 'V-245839'
  tag rid: 'SV-245839r917352_rule'
  tag stig_id: 'IS-11.03.01'
  tag gtitle: 'IS-11.03.01'
  tag fix_id: 'F-49225r917242_fix'
  tag satisfies: ['Destruction of Classified and Unclassified Documents', 'Equipment and Media - Policy/Procedure']
  tag 'documentable'
  tag legacy: ['V-32090', 'SV-42407r3_rule']
end
