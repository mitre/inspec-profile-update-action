control 'SV-245765' do
  title 'Foreign National (FN) Physical Access Control - Areas Containing US Only Information Systems Workstations/Monitor Screens, Equipment, Media or Documents'
  desc %q(Physically co-locating REL Partners or other FN - who have limited or no access to the SIPRNet or other US Classified systems - near US personnel in a collateral classified (Secret or higher) open storage area or in a Secret or higher Controlled Access Area (CAA) that processes classified material is permissible for operational efficiency and coordination.

Failure to limit and control physical access to information visible on system monitor screens, information processing equipment containing classified data, removable storage media and printed documents is especially important in mixed US/FN environments.  Inadequate access and procedural controls can result in FN personnel having unauthorized access to classified materials and data, which can result in the loss or compromise of classified information, including NOFORN information. 
   
Appropriate but simple physical and procedural security measures must be put in place to ensure the FN partners do not have unauthorized access to information not approved for release to them. 

The primary control measure is to either keep US Only classified documents, information systems equipment and/ or associated removable storage media under continuous observation and control of a cleared US employee or place such items in an approved safe when unattended.

Additionally, escorting  visitors AND all FN employees/personnel into any area where there is US Only classified processing, documents, media, equipment or materials is not only a prudent security measure but an absolute requirement to prevent both intentional (insider threat) or unintentional (inadvertent) unauthorized exposure to classified materials and information.
 
Following are applicable excerpts from CJCSI 6510.01F pertaining to control of US Only workstation spaces (in particular SCIFs and secure rooms):

7. Information and Information System Access.  Access to DOD ISs is a revocable privilege and shall be granted to individuals based on need-to-know and IAW DODI 8500.2, NSTISSP No. 200, "National Policy on Controlled Access Protection" , Status of Forces Agreements for host national access, and DOD 5200.2-R, "Personnel Security System".
b. Individual foreign nationals may be granted access to specific classified U.S. networks and systems as specifically authorized under Information Sharing guidance outlined in changes to National Disclosure Policy (NDP-1).  
(1) Classified ISs shall be sanitized or configured to guarantee that foreign nationals have access only to classified information that has been authorized for disclosure to the foreign national's government or coalition, and is necessary to fulfill the terms of their assignments.
(2) U.S.-only classified workstations shall be under strict U.S. control at all times.
27. Foreign Access.
f. Foreign National Access to U.S.-Only Workstations and Network Equipment. CC/S/As shall:
(1) Maintain strict U.S. control of U.S.-only workstations and network equipment at all times.
(4) Announce presence. If a foreign national is permitted access to U.S.-controlled workstation space, the individual must be announced, must wear a badge clearly identifying him or her as a foreign national, and must be escorted at all times. In addition, a warning light must be activated if available and screens must be covered or blanked.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information.

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl A, para 7.b.(1) & (2) and Encl C, para 27.f.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PE-5, PE-18, PS-3(1), PS-6, PS-6(1), PS-6(2)

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014, Enclosure 3, paragraph 11.                                    

DoD Manual 5200.02, Procedures for the DoD Personnel Security Program (PSP), 3 April 2017, Section 6.

DoD 8570.01-M, Information Assurance Workforce Improvement Program, para C.3.2.4.8.2, C.8.2.7 & AP1.19

DoD Manual 5200.01, Volume 1, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 2, para 9.j.(1) and Encl 3,  para 5.b., 7.b.(5), 12.e.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 3, para 5, Encl 4, para 2.c., Appendix to Encl 4, para 1.f. and Encl 7.

DoD 5220.22-M (NISPOM), Incorporating Change 2, 18 May 2016, CHAPTER 10
International Security Requirements, Section 5. International Visits and Control of Foreign Nationals)
  desc 'check', 'THIS REQUIREMENT PERTAINS TO CLASSIFIED ENVIRONMENTS such as Secret or higher vaults or classified open storage areas (secure rooms or SCIFs) WHERE FN partners ARE PRESENT with limited or no access to classified information /systems; in particular the SIPRNet. This is important to note, because without the FN presence in such an environment, placement of classified documents and classified removable media in safes when unattended would not normally be necessary/required.

CHECK #1: Check to ensure all classified and sensitive documents and removable storage media containing US Only information are either under the continuous observation and control of cleared US personnel or placed in an approved GSA container (Safe) when not in use and under proper US control.  (CAT I)
 
The requirement in check #2 is complementary to the requirement covered in check #1. Unescorted access to areas where US Only classified equipment, documents and media are present must not be granted to any FN (regardless of clearance level) when cleared US personnel are not present to provide oversight.
   
CHECK #2: Check to ensure FN access to classified open storage areas (includes vaults, secure rooms, and SCIFs) containing SIPRNet assets is permitted only during normal working hours when US personnel are present to provide oversight.  (CAT I)

TACTICAL ENVIRONMENT: This check is applicable where REL partners/LN/FN are employed within fixed facilities in a tactical environment with access to US Systems.'
  desc 'fix', 'This fix pertains to mixed classified environments containing US Only systems and media where FN partners are present:

1. All classified and sensitive documents and removable storage media containing US Only information must either be under the continuous observation and control of cleared US personnel or placed in an approved GSA container (Safe) when not in use and under proper US control. 

2. Foreign National (FN) access to classified open storage areas (includes vaults, secure rooms, and SCIFs) must be permitted only during normal working hours when US personnel are present to provide oversight.'
  impact 0.7
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49196r769955_chk'
  tag severity: 'high'
  tag gid: 'V-245765'
  tag rid: 'SV-245765r822826_rule'
  tag stig_id: 'FN-04.01.01'
  tag gtitle: 'FN-04.01.01'
  tag fix_id: 'F-49151r769956_fix'
  tag 'documentable'
  tag legacy: ['V-31242', 'SV-41465r3_rule']
end
