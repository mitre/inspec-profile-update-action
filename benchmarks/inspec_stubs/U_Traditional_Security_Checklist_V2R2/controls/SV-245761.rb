control 'SV-245761' do
  title 'Foreign National (FN) Systems Access - Local Nationals Overseas System Access -  (NIPRNet User)'
  desc 'Failure to subject foreign nationals to background checks could result in the loss or compromise of classified or sensitive information by foreign sources.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information 

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals 

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, para 26.c.(2)&(3)

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: AC-1, AC-2, AC-3, AC-24, CA-1, PS-4, PS-5, PM-9, MA-5(4) and IA-4(4)

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, paragraph 11.                                    

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017, paragraph 6.4.f.

DoD 8570.01-M, Information Assurance Workforce Improvement Program, para C.3.2.4.8.2, C.8.2.7 & AP1.19'
  desc 'check', 'Check that all local foreign nationals hired by DoD organizations overseas, with NIPRNet user access, are employed IAW the applicable Status of Forces Agreement (SOFA) and meet the following requirements:

1. Access to DoD ISs is authorized only by the DoD Component head in accordance with DoD, Department of State, and ODNI disclosure guidance, as applicable.
 
2. Mechanisms are in place to limit access strictly to information that has been cleared for release to the represented foreign nation, coalition, or international organization (e.g., North Atlantic Treaty Organization) in accordance with policy guidance for unclassified information such as IAW DoDD 5230.20E and DoDI 5230.27.

3. The Foreign Nationals have the following successfully adjudicated checks:

a. Host government, law enforcement and security agency checks at the city, state (province), and national level, whenever permissible by the laws of the host government.
b. Favorable DCII checks
c. FBI-HQ/ID (Where information exists regarding residence by the foreign national in the U.S. or Territory for one year or more since age 18).

TACTICAL ENVIRONMENT: This check is applicable where LN/FN are employed in a tactical environment with access to Unclassified US or Coalition Forces Systems.'
  desc 'fix', 'All local foreign nationals hired by DoD organizations overseas, with NIPRNet user access, must be employed IAW the applicable Status of Forces Agreement (SOFA)and meet the following requirements:

1. Access to DoD ISs is authorized only by the DoD Component head in accordance with DoD, Department of State, and ODNI disclosure guidance, as applicable.
 
2. Mechanisms are in place to limit access strictly to information that has been cleared for release to the represented foreign nation, coalition, or international organization (e.g., North Atlantic Treaty Organization) in accordance with policy guidance for unclassified information such as IAW DoDD 5230.20E and DoDI 5230.27.

3. The Foreign Nationals have the following successfully adjudicated checks:

a. Host government, law enforcement and security agency checks at the city, state (province), and national level, whenever permissible by the laws of the host government.
b. Favorable DCII checks
c. FBI-HQ/ID (Where information exists regarding residence by the foreign national in the U.S. or Territory for one year or more since age 18).'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49192r769943_chk'
  tag severity: 'medium'
  tag gid: 'V-245761'
  tag rid: 'SV-245761r769945_rule'
  tag stig_id: 'FN-02.02.01'
  tag gtitle: 'FN-02.02.01'
  tag fix_id: 'F-49147r769944_fix'
  tag 'documentable'
  tag legacy: ['V-31211', 'SV-41411r3_rule']
end
