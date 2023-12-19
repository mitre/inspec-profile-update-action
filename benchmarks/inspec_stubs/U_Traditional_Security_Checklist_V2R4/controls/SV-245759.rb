control 'SV-245759' do
  title 'Foreign National (FN) Systems Access - Local Nationals Overseas System Access -  (SIPRNet or Other Classified System or Classified Network being Reviewed)'
  desc 'Failure to subject foreign nationals to background checks could result in the loss or compromise of classified or sensitive information by foreign sources.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information 

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance & Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 26.c. (2) & (3)

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-1, AC-2, AC-3, AC-24, CA-1, PS-4, PS-5, PM-9, MA-5(4) and IA-4(4)

DODI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 11.
                  
DOD Manual 5200.02, Procedures for the DOD Personnel Security Program (PSP), 3 April 2017

DOD 8570.01-M, Information Assurance Workforce Improvement Program, para C.3.2.4.8.2, C.8.2.7 & AP1.19

DODD 8140.01 Cyberspace Workforce Management 

DODI 8140.02 Identifying-Tracking and Reporting of Cyberspace Workforce Requirements 

DODM 8140.03 Cyberspace Workforce Qualification and Management System'
  desc 'check', 'Check that all local foreign nationals hired by DOD organizations overseas do not have access to classified systems and information unless:

1. Permitted by National Disclosure Policy - AND

2. Allowed under the applicable Status of Forces Agreement (SOFA) - AND 

3. A proper background investigation/personnel vetting/security clearance adjudication for each FN granted access has been successfully completed IAW the SOFA and all other applicable DOD guidance. Security Clearance and access levels MUST be provided ONLY to the minimum necessary for mission accomplishment.
 
4. A Delegation of Disclosure Authority Letter (DDL) or similar approved certification method documenting approved access to US Classified information is available for review.

TACTICAL ENVIRONMENT: This check is applicable where LN/FN are employed in a tactical environment with access to US or Coalition Forces Systems.'
  desc 'fix', 'All local foreign nationals (FN) hired by DOD organizations overseas must not have access to classified systems and information unless:

1. Permitted by National Disclosure Policy and the applicable SOFA - AND 

2. A proper background investigation/personnel vetting/security clearance adjudication has been successfully completed for each FN granted systems access IAW the SOFA and all applicable DOD guidance. 

3. Security Clearance and access levels MUST ONLY be provided ONLY to the minimum necessary for mission accomplishment.
 
4. A Delegation of Disclosure Authority Letter (DDL) or similar approved certification method documenting approved access to US Classified information must be available for review.

NOTE: DODM 8570 requirements will be met until full implementation of DODM 8140.03 requirements. Implementation dates for DOD Manual 8140.03 include a two-year timeline for personnel (civilian and military) in positions coded with cybersecurity work roles and three years for personnel (civilian and military) in positions coded with work roles in any other workforce element. The dates for required qualification would be 15 February 2025 for cybersecurity work roles and the same date in February 2026 for all Defense Cyber Workforce Framework work roles.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49190r917157_chk'
  tag severity: 'high'
  tag gid: 'V-245759'
  tag rid: 'SV-245759r917322_rule'
  tag stig_id: 'FN-02.01.01'
  tag gtitle: 'FN-02.01.01'
  tag fix_id: 'F-49145r917158_fix'
  tag 'documentable'
  tag legacy: ['V-31215', 'SV-41417r3_rule']
end
