control 'SV-42814' do
  title 'Intrusion Detection System (IDS) Installation and Maintenance Personnel -   Suitability Checks'
  desc 'Failure to subject personnel who install and maintain the IDS alarms to a trustworthiness determination can result in the inadvertent or deliberate unauthorized exposure to or release of classified material.

REFERENCES:

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information 
Appendix to Enclosure 3, para 2.f.(1)&(2)
 
DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 5, Section 9, paragraphs 5-902.b. & 5-906

NIST Special Publication 800-53 (SP 800-53) 
Control: PS-2 and PS-3

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 
Encl A para 7.f. and Encl D Reference q 

Legacy DOD 5200.2-R; Personnel Security Program 
Paragraph C3.1.2.1.2.5. 

Current DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP) 3 April 2017, Paragraph 4.1.a.(3)'
  desc 'check', 'Check physical IDS - protecting vaults, secure rooms or spaces containing SIPRNet assets - to ensure that  installation and maintenance is accomplished by U.S. citizens who have been subjected to a trustworthiness determination in accordance with DoD Manual 5200.02.  Minimally installation and maintenance personnel must be subjects of a successfully adjudicated Tier 3 investigation or an older NACLAC and ANACI that is still within scope.

TACTICAL ENVIRONMENT APPLICABILITY: Apply to fixed tactical environments where IDS is installed to protect SIPRNet and other DoDIN (AKA: DISN) connected assets.'
  desc 'fix', 'Ensure that installation and maintenance of physical IDS - protecting vaults, secure rooms or spaces containing SIPRNet assets - is accomplished by U.S. citizens who have been subjected to a trustworthiness determination in accordance with DoD Manual 5200.02.  Minimally installation and maintenance personnel must be subjects of a successfully adjudicated Tier 3 investigation or an older NACLAC and ANACI that is still within scope.'
  impact 0.5
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40917r4_chk'
  tag severity: 'medium'
  tag gid: 'V-32477'
  tag rid: 'SV-42814r3_rule'
  tag stig_id: 'PE-08.02.02'
  tag gtitle: 'Intrusion Detection System (IDS) Installation and Maintenance Personnel -   Suitability Checks'
  tag fix_id: 'F-36394r4_fix'
  tag 'documentable'
end
