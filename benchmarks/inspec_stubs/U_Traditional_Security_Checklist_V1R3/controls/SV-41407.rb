control 'SV-41407' do
  title 'Foreign National System Access - Identification as FN in E-mail Address'
  desc 'Unauthorized access by foreign nationals to Information Systems can result in, among other things, security incidents, compromise of the system, or the introduction of a virus.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information 

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure A, Paragraph 7.d. 

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-1, AC-2, CA-1, and IA-4(4)

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 11.'
  desc 'check', 'When organizations grant foreign national access to U.S. DoD systems check to ensure foreign nationals granted e-mail privileges on DOD systems are clearly identified as such in their e-mail addresses IAW DoDI 8500.01, SUBJECT: Cybersecurity and CJCSI 6510.01F.
  
TACTICAL ENVIRONMENT: This check is applicable where LN/FN are employed in a tactical environment with access to US or Coalition Forces Systems.'
  desc 'fix', 'Foreign Nationals granted e-mail privileges on DOD systems must be clearly identified as such in their e-mail addresses IAW DoDI 8500.01, SUBJECT: Cybersecurity and CJCSI 6510.01F.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39932r7_chk'
  tag severity: 'medium'
  tag gid: 'V-31210'
  tag rid: 'SV-41407r3_rule'
  tag stig_id: 'FN-01.02.01'
  tag gtitle: 'Foreign National System Access - Email ID'
  tag fix_id: 'F-35110r7_fix'
  tag 'documentable'
end
