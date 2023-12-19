control 'SV-245861' do
  title 'Intrusion Detection System (IDS) Monitoring Station Personnel -  Suitability Checks'
  desc 'Failure to subject personnel who monitor the IDS alarms to a trustworthiness determination can result in the inadvertent or deliberate unauthorized access to, or release of classified material.

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
  desc 'check', 'Check that IDS - protecting vaults, secure rooms, alarmed Protected Distribution Systems (PDS), or other spaces containing SIPRNet assets - is monitored by U.S. personnel who have been subject to a trustworthiness check IAW DoD Manual 5200.02.
  
For Industrial Security (Contractor sites) ONLY:

Minimally, SECRET-cleared central station employees shall be in attendance at the alarm monitoring station in sufficient number to monitor each alarmed area within the cleared contractor facility IAW NISPOM requirements.

For all other DoD locations:

Minimally monitor station personnel must be subjects of a successfully adjudicated Tier 3 investigation or an older NACLAC and ANACI that is still within scope.

TACTICAL ENVIRONMENT APPLICABILITY: Apply to fixed tactical environments where IDS is installed to protect SIPRNet and other DoDIN (AKA: DISN) connected assets.'
  desc 'fix', 'Ensure that IDS - protecting vaults, secure rooms, alarmed Protected Distribution Systems (PDS), or other spaces containing SIPRNet assets - is monitored by U.S. personnel who have been subject to a trustworthiness check IAW DoD Manual 5200.02.
  
For Industrial Security (Contractor sites) ONLY:

Minimally, SECRET-cleared central station employees shall be in attendance at the alarm monitoring station in sufficient number to monitor each alarmed area within the cleared contractor facility IAW NISPOM requirements.

For all other DoD locations:

Minimally monitor station personnel must be subjects of a successfully adjudicated Tier 3 investigation or an older NACLAC and ANACI that is still within scope.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49292r770243_chk'
  tag severity: 'medium'
  tag gid: 'V-245861'
  tag rid: 'SV-245861r770245_rule'
  tag stig_id: 'PE-08.02.01'
  tag gtitle: 'PE-08.02.01'
  tag fix_id: 'F-49247r770244_fix'
  tag 'documentable'
  tag legacy: ['V-32457', 'SV-42794r3_rule']
end
