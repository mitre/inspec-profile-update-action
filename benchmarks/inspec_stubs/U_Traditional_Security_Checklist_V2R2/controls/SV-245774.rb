control 'SV-245774' do
  title 'Information Assurance - System Security Incidents (Identifying, Reporting, and Handling)'
  desc 'Failure to recognize, investigate and report information systems security incidents could result in the loss of confidentiality, integrity, and availability of the systems and its data.

REFERENCES:

CJCSM 6510.01B, CYBER INCIDENT HANDLING PROGRAM

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Appendix C

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
IR-1, IR-2, IR-3, IR-4, IR-5, IR-6, IR-7, IR-7(2), IR-8

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Encl 2, para 13.h.(1)-(5); Encl 3, para 18.g&h., 19.d.

DoD Manual 5200.01, Volume 1, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 2,  para 9.g., 11.c, 12.b.; Encl 3, para 7.b.(8), 17.a., 17.c.,; Glossary pg 76, activity SM 

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 6 (In its entirety - with emphasis on para 5.f.); Appendix 1 to Encl 6; Encl 7, para 5.

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI), para 4.c.; Encl 3, para 1.k.; Encl 4, para 9.c.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 1, Section 3, paragraphs: 1-303 & 1-304, Section 4, paragraph 1-401, Chapter 8, paragraphs 8-101.f. & 8-302.i.        
 
DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT), Encl 6, para 1.d.

CNSSI 1001, National Instruction on Classified Information Spillage

CNSSI 1010, 24X7 Computer Incident Response Capability (CIRC) on National Security Systems'
  desc 'check', '1. Check to ensure there are written procedures for identifying, reporting, and handling systems security incidents. 

2. Check to ensure that procedures for handling system security incidents are included in both initial and annual (refresher) employee training. 

NOTE: Applies in a tactical environment. While procedures for incident handling might not be readily available in a mobile/field location, they should be established and available at a supporting fixed headquarters facility.  Field units must still be informed and knowledgeable of their responsibility to report security incidents. This knowledge can be ascertained by asking field organization leadership what they would do in a spillage or similar computer security incident.'
  desc 'fix', 'A program to recognize, investigate, and report information systems security incidents to include virus, system penetration, and classified contamination must be established. Such a program will include written procedures that are available for employee review as well as including the topic in initial and annual security refresher training.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49205r769982_chk'
  tag severity: 'medium'
  tag gid: 'V-245774'
  tag rid: 'SV-245774r822835_rule'
  tag stig_id: 'IA-03.02.01'
  tag gtitle: 'IA-03.02.01'
  tag fix_id: 'F-49160r769983_fix'
  tag 'documentable'
  tag legacy: ['V-31008', 'SV-41055r3_rule']
end
