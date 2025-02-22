control 'SV-245868' do
  title 'Visitor Control  - To Facility or Organization with Information System Assets Connected to the DISN'
  desc 'Failure to identify and control visitors could result in unauthorized personnel gaining access to the
facility with the intent to compromise classified information, steal equipment, or damage equipment
or the facility.

REFERENCES:

DoD 5200.8-R Physical Security Program 
Chap 3, para C3.3.1.4. and DL1.17. on pg 8 and DTM 09-012, 8 Dec 09, Incorporating Change 7, Effective April 17, 2017  

DoD Manual 5200.08 Volume 3, Physical Security Program: Access to DoD Installations, 2 January 2019

DoD 5220.22-M (NISPOM), February 2006, Incorporating Change 2, May 18, 2016
Chapter 6, Visits and Meetings

NIST Special Publication 800-53 (SP 800-53) 
Controls: PE-2, PE-3 and PE-8 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), 9 February 2011 
Encl C, para 34. 

DoD Manual 5200.01, Volume 3, 24 February 2012, SUBJECT: DoD Information Security Program: Protection of Classified Information 
Glossary, definition of security-in-depth and Encl 2, para 7.a and 7.b.'
  desc 'check', 'Review visitor control procedures and implementation and ensure they include verification of clearance/investigation status (where required for access), personal identification of visitor, registering of visitors, proper badging (using DoD issued Common Access Cards (CAC) or other authorized credentials) and escorts. 

NOTE 1: Traditional Security reviewers may be able to evaluate implementation of the visitor process by reviewing how the review team was identified and badged. 

NOTE 2: Detailed audit logs of all facility visitors should be maintained for at least 90 days.  Automated Entry Control System (AECS) electronic logs may be used to meet this requirement.  

NOTE 3: Additional interviews can be conducted with personnel handling the visitor control function.
                                            
TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', 'Review visitor control procedures and implementation and ensure they include verification of clearance/investigation status (where required for access), personal identification of visitor, registering of visitors, proper badging (using DoD issued Common Access Cards (CAC) or other authorized credentials) and escorts. 

NOTE: Detailed audit logs of all facility visitors should be maintained for at least 90 days.  Automated Entry Control System (AECS) electronic logs may be used to meet this requirement.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49299r770264_chk'
  tag severity: 'medium'
  tag gid: 'V-245868'
  tag rid: 'SV-245868r822931_rule'
  tag stig_id: 'PH-06.02.01'
  tag gtitle: 'PH-06.02.01'
  tag fix_id: 'F-49254r770265_fix'
  tag 'documentable'
  tag legacy: ['V-32602', 'SV-42939r3_rule']
end
