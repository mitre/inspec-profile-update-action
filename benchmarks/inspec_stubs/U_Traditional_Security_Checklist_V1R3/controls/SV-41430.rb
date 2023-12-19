control 'SV-41430' do
  title 'Foreign National (FN) Systems Access - Local Nationals (LN) Overseas System Access -  Vetting for Privileged Access'
  desc 'Failure to subject foreign nationals to appropriate background checks could result in the loss or compromise of classified or sensitive information by foreign sources.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information
 
Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 26.c. (2) & (3) and para 27.e.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-1, AC-2, AC-3, AC-24, CA-1, PS-4, PS-5, PM-9, MA-5(4) and IA-4(4)

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 11.  
                          
DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017

DoD 8570.01-M, Information Assurance Workforce Improvement Program, para C1.4.4.6.4, C3.2.4.8., C3.2.4.8.2., C10.2.3.7.2., C11.2.4.7., AP1.22.'
  desc 'check', 'When local foreign nationals are hired by DOD organizations overseas IAW the applicable Status of Forces Agreement (SOFA) and are assigned to Cyber Security (AKA: Information Assurance (IA)) positions of trust: 

1. Check to ensure they comply with background investigation requirements (SSBI or equivalent) AND that they are not assigned to any IAM Level III positions or IAT Level III positions of trust IAW DoD 8570.01-M, IA Workforce Improvement Program.  

2. Check to ensure that Local Nationals (LN) and Foreign Nationals (FN) are always supervised by a higher level Information Assurance (IA) position that is occupied by a US Government employee who is a US citizen. 

3. Check to ensure that the Information Assurance Manager is never a LN/FN. 

TACTICAL ENVIRONMENT: This check is applicable where LN/FN are employed in a tactical environment with access to US or Coalition Forces Systems.'
  desc 'fix', 'When local foreign nationals are hired by DOD organizations overseas IAW the applicable SOFA and are assigned to Cyber Security (AKA: Information Assurance (IA)) positions of trust: 

1. They must have successfully completed and comply with background investigation requirements (SSBI or equivalent) 

2. They must not be assigned to any IAM Level III positions or IAT Level III positions of trust IAW DoD 8570.01-M, IA Workforce Improvement Program. 

3. A Local National (LN) or Foreign National (FN) employed in an information system position of trust must always be supervised by a higher level IA position occupied by a US Government employee who is also a US citizen. 

4. An Information Assurance Manager must never be a LN or FN.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39946r7_chk'
  tag severity: 'high'
  tag gid: 'V-31221'
  tag rid: 'SV-41430r3_rule'
  tag stig_id: 'FN-02.01.02'
  tag gtitle: 'FN System Access -  Local Nationals (LN) Overseas Systems Access -  (Privileged Access)'
  tag fix_id: 'F-35118r4_fix'
  tag 'documentable'
end
