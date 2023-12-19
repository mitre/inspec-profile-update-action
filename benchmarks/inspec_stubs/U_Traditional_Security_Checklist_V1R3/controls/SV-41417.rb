control 'SV-41417' do
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

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 11.
                                   
DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017

DoD 8570.01-M, Information Assurance Workforce Improvement Program, para C.3.2.4.8.2, C.8.2.7 & AP1.19'
  desc 'check', 'Check that all local foreign nationals hired by DoD organizations overseas do not have access to classified systems and information unless:

1. Permitted by National Disclosure Policy - AND

2. Allowed under the applicable Status of Forces Agreement (SOFA) - AND 

3. A proper background investigation/personnel vetting/security clearance adjudication for each FN granted access has been successfully completed IAW the SOFA and all other applicable DoD guidance. Security Clearance and access levels MUST be provided ONLY to the minimum necessary for mission accomplishment.
 
4. A Delegation of Disclosure Authority Letter (DDL) or similar approved certification method documenting approved access to US Classified information is available for review.

TACTICAL ENVIRONMENT: This check is applicable where LN/FN are employed in a tactical environment with access to US or Coalition Forces Systems.'
  desc 'fix', 'All local foreign nationals (FN) hired by DoD organizations overseas must not have access to classified systems and information unless:

1. Permitted by National Disclosure Policy and the applicable SOFA - AND 

2. A proper background investigation/personnel vetting/security clearance adjudication has been successfully completed for each FN granted systems access IAW the SOFA and all applicable DoD guidance. 

3. Security Clearance and access levels MUST ONLY be provided ONLY to the minimum necessary for mission accomplishment.
 
4. A Delegation of Disclosure Authority Letter (DDL) or similar approved certification method documenting approved access to US Classified information must be available for review.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39943r5_chk'
  tag severity: 'high'
  tag gid: 'V-31215'
  tag rid: 'SV-41417r3_rule'
  tag stig_id: 'FN-02.01.01'
  tag gtitle: 'Foreign national (FN) Systems Access - Local Nationals Overseas System Access -  SIPRNet'
  tag fix_id: 'F-35117r7_fix'
  tag 'documentable'
end
