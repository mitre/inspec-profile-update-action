control 'SV-245870' do
  title 'Physical Penetration Testing - of Facilities or Buildings Containing Information Systems (IS) Connected to the DISN'
  desc 'Failure to periodically test facility/building security where Information Systems (IS) connected to the DISN are present could lead to the unauthorized access of an individual into the facility with nefarious intentions to affect the Confidentiality, Integrity or Assurance of data or hardware on the IS.

REFERENCES:

DoD 5200.8-R Physical Security Program 
Chapter 2, para C2.1.3.2. C2.1.3.4. and C2.2.4.

DoD Manual 5200.08 Volume 3, Physical Security Program: Access to DoD Installations, 2 January 2019

DoD 5200.22-M (NISPOM), February 2006, Incorporating Change 2, May 18, 2016
Chapter 8, paragraph 8-101.d.

NIST Special Publication 800-53 (SP 800-53) 
Controls:  CA-2, CA-8 and PE-3(6) and PE-6

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 
Encl A, para 8.b., Encl C paragraphs 6.b. 12.a. 34. 

DoDI 8500.01, March 14, 2014, DoD CIO, SUBJECT: Cybersecurity
Encl 2, para 13.s. and Encl 3, paragraphs 3.b. & 5.c.'
  desc 'check', 'Check to ensure that procedures for a facility penetration testing process are developed that includes periodic, unannounced attempts to penetrate key computing facilities. Results of these tests should be provided to the site or organization commander/director and if applicable, the supporting base physical security specialist.  Any discrepancies should be addressed and corrective action taken (i.e., update procedures or provide additional training). 

If a test has not been completed within the last 12-months this should be a finding. 

Note: It is often a good idea for the site conducting physical penetration tests to coordinate support or this testing from supporting host installation security or an outside source.  That enables the test to be conducted by someone that most site personnel might not be familiar with and will facilitate a good test using social engineering or other methodology to gain unauthorized access.  
                                   
TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', 'Ensure that procedures for a facility penetration testing process are developed that includes periodic, unannounced attempts to penetrate key computing facilities. Results of these tests should be provided to the site or organization commander/director and if applicable, the supporting base physical security specialist.  Any discrepancies should be addressed and corrective action taken (i.e., update procedures or provide additional training). 

Ensure the test is completed at least annually.

Note: It is often a good idea for the site conducting physical penetration tests to coordinate support or this testing from supporting host installation security or an outside source.  That enables the test to be conducted by someone that most site personnel might not be familiar with and will facilitate a good test using social engineering or other methodology to gain unauthorized access.'
  impact 0.3
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49301r770354_chk'
  tag severity: 'low'
  tag gid: 'V-245870'
  tag rid: 'SV-245870r770356_rule'
  tag stig_id: 'PH-09.03.01'
  tag gtitle: 'PH-09.03.01'
  tag fix_id: 'F-49256r770355_fix'
  tag 'documentable'
  tag legacy: ['V-32604', 'SV-42941r3_rule']
end
