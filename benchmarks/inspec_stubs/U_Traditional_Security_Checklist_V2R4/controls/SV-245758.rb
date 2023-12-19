control 'SV-245758' do
  title 'Foreign National System Access - Local Access Control Procedures'
  desc 'Unauthorized access by foreign nationals to Information Systems can result in, among other things, security incidents, compromise of the system, or the introduction of a virus.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information 

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-1, AC-2, AC-3, AC-24, PS-4, PS-5, CA-1, MA-5(4) and IA-4(4)

DODI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 11. 
                 
DOD Manual 5200.02, Procedures for the DOD Personnel Security Program (PSP), 3 April 2017

DOD 8570.01-M, Information Assurance Workforce Improvement Program 

DODD 8140.01 Cyberspace Workforce Management 

DODI 8140.02 Identifying-Tracking and Reporting of Cyberspace Workforce Requirements 

DODM 8140.03 Cyberspace Workforce Qualification and Management System'
  desc 'check', '1. When organizations grant foreign nationals access to U.S. DOD systems check to ensure there are written procedures to guide system administrators. 

There are numerous categories of foreign military and civilian personnel, which should be addressed, as applicable to the site or organization and include the following:

- Foreign Liaison Officers (FLO)
- Foreign Exchange Officers 
- REL Partners
- Coalition Partners
- Foreign Nationals/Local Nationals (FN/LN) employed by DOD Organizations Overseas under SOFA       
- Foreign Nationals employed by Government contractors       
- Foreign Nationals or immigrant aliens not affiliated with or representing their Country of citizenship, who may be granted a Limited Access Authorization (LAA) for access to US Classified.

2. Reviewers must validate that local procedures adequately cover all possible foreign national encounters applicable to the site and ensure guidance is correct and follows regulatory standards. 

3. Reviewers must ensure system access request forms used clearly indicate that the applicant for systems access is a foreign national. 

TACTICAL ENVIRONMENT: This check is applicable where LN/FN are employed in a tactical environment with access to US or Coalition Forces Systems.'
  desc 'fix', '1. Local written procedures to guide system administrators must be developed when granting foreign nationals access to U.S. DOD systems 

NOTE: There are numerous categories of foreign military and civilian personnel, which should be addressed, as applicable to the site or organization and include the following:

- Foreign Liaison Officers (FLO) 
- Foreign Exchange Officers 
-REL Partners - Coalition Partners 
- Foreign Nationals/Local Nationals (FN/LN) employed by DOD Organizations Overseas under SOFA 
- Foreign Nationals employed by Government contractors 
- Foreign Nationals or immigrant aliens not affiliated with or representing their Country of citizenship, who may be granted a Limited Access Authorization (LAA) for access to US Classified.
 
2. Local procedures must cover all possible foreign national encounters applicable to the site and ensure guidance is correct and follows regulatory standards.
 
3. System Access Authorization Request (SAAR) forms used by the site must clearly indicate the applicant for systems access is a foreign national.

NOTE: DODM 8570 requirements will be met until full implementation of DODM 8140.03 requirements. Implementation dates for DOD Manual 8140.03 include a two-year timeline for personnel (civilian and military) in positions coded with cybersecurity work roles and three years for personnel (civilian and military) in positions coded with work roles in any other workforce element. The dates for required qualification would be 15 February 2025 for cybersecurity work roles and the same date in February 2026 for all Defense Cyber Workforce Framework work roles.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49189r917154_chk'
  tag severity: 'low'
  tag gid: 'V-245758'
  tag rid: 'SV-245758r917321_rule'
  tag stig_id: 'FN-01.03.01'
  tag gtitle: 'FN-01.03.01'
  tag fix_id: 'F-49144r917155_fix'
  tag 'documentable'
  tag legacy: ['V-31199', 'SV-41387r3_rule']
end
