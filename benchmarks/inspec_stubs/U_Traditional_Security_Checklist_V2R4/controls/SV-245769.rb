control 'SV-245769' do
  title 'Foreign National (FN) Administrative Controls - Procedures for Requests to Provide Foreign Nationals System Access'
  desc 'Unauthorized access by foreign nationals to Information Systems can result in, among other things, security incidents, compromise of the system, or the introduction of a virus.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information.

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraphs 26.c.(3) and 27.f.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
CA-1, AC-2, AC-3, PS-1, PS-2 and PS-3

DODI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 11.                  

DOD Manual 5200.02, Procedures for the DOD Personnel Security Program (PSP), 3 April 2017

DOD Manual 5200.01, Volume 1, SUBJECT: DOD Information Security Program: Overview, Classification, and Declassification, Encl 2, para 9.j.(1).

DOD Manual 5200.01, Volume 3, SUBJECT: DOD Information Security Program: Protection of Classified Information, Encl 7

DOD 8570.01-M, Information Assurance Workforce Improvement Program, para C.3.2.4.8.2, & AP1.19

DODD 8140.01 Cyberspace Workforce Management 

DODI 8140.02 Identifying-Tracking and Reporting of Cyberspace Workforce Requirements 

DODM 8140.03 Cyberspace Workforce Qualification and Management System

DOD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, CHAPTER 10
International Security Requirements, Section 5. International Visits and Control of Foreign Nationals'
  desc 'check', 'Check to ensure there are local written procedures for when foreign national request access to U.S. systems. 

Validate the standards are correct. 

Ensure Foreign Nationals only hold IT positions authorized by regulation - primarily DOD 8570.01-M, IA Workforce Improvement Program. 

TACTICAL ENVIRONMENT: This check is applicable where REL partners/LN/FN are employed in a tactical environment with access to classified or unclassified US Systems or Coalition Systems.'
  desc 'fix', 'There must be local written procedures for when there is a foreign national request to access to U.S. systems. 

Foreign Nationals must only hold IT positions authorized by regulation. IAW DOD 8570.01-M: C3.2.4.8.2. ...LNs and Foreign Nationals (FNs) must comply with background investigation requirements and cannot be assigned to IAT Level III positions.     

TACTICAL ENVIRONMENT: This check is applicable where REL partners/LN/FN are employed in a tactical environment with access to classified or unclassified US Systems or Coalition Systems.

NOTE: DODM 8570 requirements will be met until full implementation of DODM 8140.03 requirements. Implementation dates for DOD Manual 8140.03 include a two-year timeline for personnel (civilian and military) in positions coded with cybersecurity work roles and three years for personnel (civilian and military) in positions coded with work roles in any other workforce element. The dates for required qualification would be 15 February 2025 for cybersecurity work roles and the same date in February 2026 for all Defense Cyber Workforce Framework work roles.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49200r917180_chk'
  tag severity: 'medium'
  tag gid: 'V-245769'
  tag rid: 'SV-245769r917330_rule'
  tag stig_id: 'FN-05.02.02'
  tag gtitle: 'FN-05.02.02'
  tag fix_id: 'F-49155r917181_fix'
  tag 'documentable'
  tag legacy: ['V-31265', 'SV-41516r3_rule']
end
