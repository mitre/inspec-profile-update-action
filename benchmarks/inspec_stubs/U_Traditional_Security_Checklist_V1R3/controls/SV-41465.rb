control 'SV-41465' do
  title 'Foreign National (FN) Physical Access Control - Areas Containing US Only Information Systems Workstations/Monitor Screens, Equipment, Media or Documents'
  desc 'Physically co-locating REL Partners or other FN - who have limited or no access to the SIPRNet or other US Classified systems - near US personnel in a collateral classified (Secret or higher) open storage area or in a Secret or higher Controlled Access Area (CAA) that processes classified material is permissible for operational efficiency and coordination.

Failure to limit and control physical access to information visible on system monitor screens, information processing equipment containing classified data, removable storage media and printed documents is especially important in mixed US/FN environments.  Inadequate access and procedural controls can result in FN personnel having unauthorized access to classified materials and data, which can result in the loss or compromise of classified information, including NOFORN information. 
   
Appropriate but simple physical and procedural security measures must be put in place to ensure the FN partners do not have unauthorized access to information not approved for release to them. 

The primary control measure is to either keep US Only classified documents, information systems equipment and/ or associated removable storage media under continuous observation and control of a cleared US employee or place such items in an approved safe when unattended.

Additionally, escorting  visitors AND all FN employees/personnel into any area where there is US Only classified processing, documents, media, equipment or materials is not only a prudent security measure but an absolute requirement to prevent both intentional (insider threat) or unintentional (inadvertent) unauthorized exposure to classified materials and information.
 
Following are applicable excerpts from CJCSI 6510.01F pertaining to control of US Only workstation spaces (in particular SCIFs and secure rooms):

7. Information and Information System Access.  Access to DOD ISs is a revocable privilege and shall be granted to individuals based on need-to-know and IAW DODI 8500.2, NSTISSP No. 200, “National Policy on Controlled Access Protection” , Status of Forces Agreements for host national access, and DOD 5200.2-R, “Personnel Security System”.
b. Individual foreign nationals may be granted access to specific classified U.S. networks and systems as specifically authorized under Information Sharing guidance outlined in changes to National Disclosure Policy (NDP-1).  
(1) Classified ISs shall be sanitized or configured to guarantee that foreign nationals have access only to classified information that has been authorized for disclosure to the foreign national’s government or coalition, and is necessary to fulfill the terms of their assignments.
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

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, CHAPTER 10
International Security Requirements, Section 5. International Visits and Control of Foreign Nationals'
  desc 'check', 'THIS REQUIREMENT PERTAINS TO CLASSIFIED ENVIRONMENTS such as Secret or higher vaults or classified open storage areas (secure rooms or SCIFs) WHERE FN partners ARE PRESENT with limited or no access to classified information /systems; in particular the SIPRNet. This is important to note, because without the FN presence in such an environment, placement of classified documents and classified removable media in safes when unattended would not normally be necessary/required.

CHECK #1: Check to ensure all classified and sensitive documents and removable storage media containing US Only information are either under the continuous observation and control of cleared US personnel or placed in an approved GSA container (Safe) when not in use and under proper US control.  (CAT I)
 
The requirement in check #2 is complementary to the requirement covered in check #1. Unescorted access to areas where US Only classified equipment, documents and media are present must not be granted to any FN (regardless of clearance level) when cleared US personnel are not present to provide oversight.
   
CHECK #2: Check to ensure FN access to classified open storage areas (includes vaults, secure rooms, and SCIFs) containing SIPRNet assets is permitted only during normal working hours when US personnel are present to provide oversight.  (CAT I)

TACTICAL ENVIRONMENT: This check is applicable where REL partners/LN/FN are employed within fixed facilities in a tactical environment with access to US Systems.'
  desc 'fix', 'This fix pertains to mixed classified environments containing US Only systems and media where FN partners are present:

1. All classified and sensitive documents and removable storage media containing US Only information must either be under the continuous observation and control of cleared US personnel or placed in an approved GSA container (Safe) when not in use and under proper US control. 

2. Foreign National (FN) access to classified open storage areas (includes vaults, secure rooms, and SCIFs) must be permitted only during normal working hours when US personnel are present to provide oversight.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39965r11_chk'
  tag severity: 'high'
  tag gid: 'V-31242'
  tag rid: 'SV-41465r3_rule'
  tag stig_id: 'FN-04.01.01'
  tag gtitle: 'FN Physical Access Control  - Areas Containing Classified US Only Information Systems'
  tag fix_id: 'F-35136r6_fix'
  tag 'documentable'
  tag severity_override_guidance: 'The default severity level is Category I and there is no mitigation allow to a lower severity level.

This check is to assess physical access control measures and control and internal control procedures for classified information system equipment and removable storage media in areas in which there are US Only terminals/monitors/documents/media or other US Only system/network equipment.  Even though there may also be terminals/monitors/documents/media or other system/network equipment present in the same area to which FN have been granted access, the fact the FN do not have access to the US Only equipment requires that the FN are not granted unescorted physical access to such areas.

Therefore, if there are absolutely no US Only classified / sensitive work stations, monitors, documents or media in an area (with FN presence) and the FN employee or partner has been granted access to all systems in the physical environment - then this requirement is NA and should be annotated to the VMS report as Not a Finding.

This requirement is also NA if there is no routine FN presence in the classified work area.'
  tag potential_impacts: 'RELATED VULS (STIG ID):

1.  STIG ID: FN-05.02.01.  This requirement is specifically focused on checking written policy/procedures and initial/recurring training concerning US employee interactions with FN employees assigned to the organization OR frequent and recurring FN visitors.  Even if there are procedures and training a finding may still be written when it is clear from interviews and observation of the environment by traditional security reviewers that a lack of employee understanding of the rules and procedures are evident and are not being exercised.

2.  STIG ID: IS-08.01.01.  Classified Monitors/Displays (Physical Control of Classified Monitors From Unauthorized Viewing).  This requirement is specifically focused on checking physical controls in place to protect classified work stations (monitor screens) from unauthorized viewing.  This requirement includes positioning and control of classified monitors and covers environments where Foreign Nationals are present and US Only work stations/monitor screens are present.
 
3.  STIG ID: IS-08.03.01.  This requirement is specifically focused on checking written policy/procedures and initial/recurring training concerning cleared employee responsibilities and actions to protect classified work stations (monitor screens) under their control from unauthorized viewing.  This requirement includes positioning and control of classified monitors and covers environments containing  US Only work stations/monitor screens where Foreign Nationals are present.  

4.  STIG ID: IS-08.01.02.  This requirement concerns maintaining control of Common Access Cards (CACs), SIPRNet tokens and locking of computer work stations/monitor screens when unattended by removal of CACs, SIPRNet tokens or using Clt/Alt/Del.  This requirement includes environments containing  US Only work stations/monitor screens where Foreign Nationals are present.'
end
