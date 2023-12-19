control 'SV-41436' do
  title 'Foreign National (FN) System Access - FN or Immigrant Aliens (not representing a foreign government or entity) with LAA Granted Uncontrolled Access'
  desc 'Failure to verify citizenship and proper authorization for access to either sensitive or classified information could enable personnel to have access to classified or sensitive information to which they are not entitled.  Further uncontrolled/unsupervised access to physical facilities can lead directly to unauthorized access to classified or sensitive information.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information.

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 26.c.(2)&(3)

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-1, AC-2, AC-3, AC-24, CA-1, PS-3, PS-4, PS-5, PM-9, MA-5(4) and IA-4(4)

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 11.                                    

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017, Section 6.

DoD 8570.01-M, Information Assurance Workforce Improvement Program, para C.3.2.4.8.2, C.8.2.7 & AP1.19

DoD Manual 5200.01, Volume 1, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 2, para 9.j.(1) and Encl 3,  para 5.b., 7.b.(5), 12.e.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 3, para 5, Encl 4, para 2.c., Appendix to Encl 4, para 1.f. and Encl 7.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, CHAPTER 10
International Security Requirements, Section 5. International Visits and Control of Foreign Nationals and Section 6. Contractor Operations Abroad, paragraph 10-601.b.'
  desc 'check', '1. Check to ensure that personnel granted LAAs are not permitted uncontrolled access to areas where classified information is stored or discussed (safes, vaults and secure room in particular). Classified information must be maintained in a location that will be under the continuous control and supervision of an appropriately cleared U.S. citizen.  

2. Check to ensure that access to DoD information systems is properly controlled so that any FN granted an LAA has systems access only to that sensitive (CUI) or classified information to which they are specifically authorized. This check will require close coordination and consultation with a network reviewer or SME.  

TACTICAL ENVIRONMENT: This check is applicable where any non-U.S. citizens (not representing a foreign Government or entity) are employed in a tactical environment with access to US Classified or Sensitive Systems.'
  desc 'fix', '1. Personnel granted LAAs must not be permitted uncontrolled access to areas where classified information is stored or discussed (safes, vaults and secure room in particular). Classified information must be maintained in a location that will be under the continuous control and supervision of an appropriately cleared U.S. citizen.           

2. Access granted to DoD information systems must be properly controlled so that any FN granted an LAA has systems access only to that sensitive (CUI) or classified information to which they are specifically authorized.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39953r5_chk'
  tag severity: 'high'
  tag gid: 'V-31227'
  tag rid: 'SV-41436r3_rule'
  tag stig_id: 'FN-03.01.02'
  tag gtitle: 'Foreign National (FN) System Access/Immigrant Aliens with LAA -Uncontrolled Access'
  tag fix_id: 'F-35131r5_fix'
  tag 'documentable'
end
