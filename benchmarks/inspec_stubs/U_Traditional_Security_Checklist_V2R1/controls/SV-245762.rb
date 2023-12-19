control 'SV-245762' do
  title 'Foreign National (FN) Systems Access - Delegation of Disclosure Authority Letter (DDL)'
  desc 'Unauthorized access by foreign nationals to Information Systems can result in, among other things, security incidents, compromise of the system, or the introduction of a virus.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information -- Specifically note paragraphs 4.6.3., E2.1.4. and Enclosure 4.

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals, paragraph 4.4.

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 26.c.(2)&(3)

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-1, AC-2, AC-3, AC-24, CA-1, PS-4, PS-5, PM-9, MA-5(4) and IA-4(4)

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 11.                                    

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017

DoD 8570.01-M, Information Assurance Workforce Improvement Program, para C.3.2.4.8.2, C.8.2.7 & AP1.19'
  desc 'check', "1. Check that a Delegation of Disclosure Authority Letter (DDL) is on hand for each assigned REL partner or other FN partner granted Limited Access to US Classified.  

NOTE: All disclosures and denials of classified military information are reported in the Foreign Disclosure and Technical Information System (FORDTIS) and it might also be possible for reviewers to request visual access to validate foreign clearance approvals at sites. However, a DDL is required for access to any US Classified information. 

2. The organization's supporting Foreign Disclosure/Contact Officer (FDO) will be the ultimate POC for this.    

TACTICAL ENVIRONMENT: This check is applicable where REL Partners or other FN allies are employed in a tactical environment with access to US Classified or Sensitive Systems."
  desc 'fix', "A Delegation of Disclosure Authority Letter (DDL) must be on hand for each assigned REL partner or other FN partner granted Limited Access to US Classified systems or information. 

NOTE 1:  All disclosures and denials of classified military information are reported in the Foreign Disclosure and Technical Information System (FORDTIS). A DDL is required to validate and set parameters for FN access to any US Classified information. 

NOTE 2: The organization's supporting Foreign Disclosure/Contact Officer (FDO) will be the POC for this."
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49193r769946_chk'
  tag severity: 'medium'
  tag gid: 'V-245762'
  tag rid: 'SV-245762r769948_rule'
  tag stig_id: 'FN-02.02.02'
  tag gtitle: 'FN-02.02.02'
  tag fix_id: 'F-49148r769947_fix'
  tag 'documentable'
  tag legacy: ['V-31223', 'SV-41432r3_rule']
end
