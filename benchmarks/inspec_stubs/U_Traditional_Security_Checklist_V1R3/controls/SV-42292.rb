control 'SV-42292' do
  title 'Monitor Screens - Disable Access by CAC or Token Removal, or Lock Computer via Ctrl/Alt/Del'
  desc 'The DoD Common Access Cards (CAC) a "smart" card, is the standard identification for active-duty military personnel, Selected Reserve, DoD civilian employees, and eligible contractor personnel.  It is also the principal card used to enable physical access to buildings and controlled spaces, and it provides access to defense computer networks and systems. 
 
The card, which is the property of the U.S. Government, is required to be in the personal custody of the member at all times.

System Access Tokens are also used on the SIPRNet and the cards along with a Personal identity Number (PIN) can be used to access classified information on the SIPRNet in lieu of a logon ID and password.

CAC and SIPRNet tokens are very important components for providing both physical and logical access control to DISN assets and must therefore be strictly controlled.

Physically co-locating REL Partners or other FN - who have limited access to the SIPRNet or other US Classified systems - near US personnel in a collateral classified (Secret or higher) open storage area or in a Secret or higher Controlled Access Area (CAA) that processes classified material is permissible for operational efficiency and coordination.
  
Failure to limit access to information systems is especially important in mixed US/FN environments.   This is particularly important on US Only classified terminals when not personally and physically attended by US personnel.  The failure to properly disable information workstations and monitor screens when unattended can result in FN personnel having unauthorized access to classified information, which can result in the loss or compromise of classified information, including NOFORN information. 

Appropriate but simple physical and procedural security measures must be put in place to ensure that unauthorized persons to include FN partners do not have unauthorized access to information not approved for release to them.  Control of CACs, SIPRNet tokens and locking of computer work stations when unattended is an important aspect of proper procedural security measure implementation.

REFERENCES:

National Disclosure Policy - 1 (NDP-l) 

National Security Directive 42, "National Policy for the Security of National Security Telecommunications and Information Systems 

DODD 5230.11, Disclosure of Classified Military Information to Foreign Governments and International Organizations SPECIAL NOTE: Enclosure 3 to DODD 5230.11 establishes specific criteria for the disclosure of classified information.

Use guidance on sharing information with REL Partners on SIPRNET at http://www.ssc.smil.mil/ - follow Policy/Guidance&Documentation link and then SIPRNet Information Sharing...

Homeland Security Presidential Directive-12 (HSPD-12), "Policy for a Common Identification Standard for Federal Employees and Contractors," 27 August 2004 

DoD Manual 1000.13, Volume 1, SUBJECT: DoD Identification (ID) Cards: ID Card Life-Cycle, 
January 23, 2014

DoD Manual 1000.13, Volume 2, SUBJECT: DoD Identification (ID) Cards: Benefits for Members of the Uniformed Services, Their Dependents, and Other Eligible Individuals,  January 23, 2014

UNDER SECRETARY OF DEFENSE (Intelligence), Directive-Type Memorandum (DTM) 09-012, "Interim Policy Guidance for DoD Physical Access Control", December 8, 2009, Incorporating Change 6, Effective November 20, 2015

DoDI 1000.13, SUBJECT: Identification (ID) Cards for Members of the Uniformed Services, Their Dependents, and Other Eligible Individuals, January 23, 2014 

DoDI 8520.02 , SUBJECT: Public Key Infrastructure (PKI) and Public Key (PK) Enabling, May 24, 2011 

DODD 5230.20; Visits, Assignments, and Exchanges of Foreign Nationals

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure C, paragraph 26.d.,  27.d.(e) and 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
IA-2, IA-4, PL-4, PS-6, PS-8, AC-3, AC-11, SC-28

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 3, 
paragraph 8.                                    

DoD Manual 5200.01, Volume 1, SUBJECT: DoD Information Security Program: Overview, Classification, and Declassification, Encl 2, para 9.j.(1) and Encl 3,  para 5.b., 7.b.(5), 12.e.

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 3, para 5; Encl 4, para 2.c. ;Appendix to Encl 4, para 1.f. and Encl 7.

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraph 8-103.'
  desc 'check', 'Check to ensure:

1. SIPRNet servers and/or work station hard drives/monitors/keyboards are disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted and cleared US personnel.  (CAT I)

2. NIPRNet servers and/or work station hard drives/monitors/keyboards (*used by system administrators with privileged access) are disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted US personnel.  (CAT I)

3. NIPRNet work station hard drives/monitors/keyboards (*used by general users or individuals without privileged systems access) are disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted US personnel. (CAT II)

4. CACs and other tokens are not left unattended and are in the physical custody of the person to whom they were issued. (CAT II)

TACTICAL ENVIRONMENT:  This check is applicable to all environments (including a field/mobile tactical environment) where information system assets are connected to the DISN.'
  desc 'fix', '1.  SIPRNet servers and/or work station hard drives/monitors/keyboards must be disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted and cleared US personnel.

2.  NIPRNet servers and/or work station hard drives/monitors/keyboards must be disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted US personnel.

3.  CACs and other tokens must not be left unattended and must be in the physical custody of the person to whom they were issued.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-40633r9_chk'
  tag severity: 'high'
  tag gid: 'V-31993'
  tag rid: 'SV-42292r3_rule'
  tag stig_id: 'IS-08.01.02'
  tag gtitle: 'Monitor Screens - Disable Access by CAC or Token Removal, or Lock Computer via Ctrl/Alt/Del'
  tag fix_id: 'F-35925r5_fix'
  tag 'documentable'
  tag severity_override_guidance: 'The default severity level is Category I (CAT I) based on the following requirement to lock server, work station and monitor screens connected to the DISN (SIPRNet and NIPRNet)  when not physically attended:

SIPRNet servers and/or work station hard drives/monitors/keyboards are disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted and cleared US personnel.  (CAT I)

NIPRNet servers and/or work station hard drives/monitors/keyboards (*used by system administrators with privileged access) are disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted US personnel.  (CAT I)

If the above deficiencies are not discovered (All SIPRNet workstations, and/or NIPRNet workstations with privileged access are properly locked when unattended ) but a CAC or SIPRNet Token is discovered not under the personal control of the person to whom it was issued then the finding may be reduced to CAT II.  Following is the applicable finding relative to a CAT II severity level:

CACs and other tokens are not left unattended and are in the physical custody of the person to whom they were issued. (CAT II)

Additionally the following finding may default as a CAT II if a CAC is found unattended in a NIPRNet workstation card reader, where the CAC holder has only non-privileged access:

NIPRNet work station hard drives/monitors/keyboards (*used by general users or individuals without privileged systems access) are disabled (locked) by CAC or Token Removal, or where CACs or tokens are not used the Computer must be locked via Ctrl/Alt/Del - when not personally and physically attended by properly vetted US personnel.  (CAT II)'
  tag potential_impacts: 'RELATED VULS (STIG ID):

1.  STIG ID: FN-04.01.01.  This requirement concerns two related concerns.  First is control of physical access to areas containing US Only workstations/monitor screens, equipment, media or documents in working environments where Foreign Nationals are employed or present. Second, It also covers maintaining continuous observation and control of US Only classified information system removable storage media and documents within classified storage locations (such as SCIFs, secure rooms or vaults) where foreign nationals are present OR or placement in an approved safe.     

2.  STIG ID: IS-08.01.01.  Classified Monitors/Displays (Physical Control of Classified Monitors From Unauthorized Viewing) .  This requirement is specifically focused on checking physical controls in place to protect classified work stations (monitor screens) from unauthorized viewing.  This requirement includes positioning and control of classified monitors and covers environments where  Foreign Nationals are present and US Only work stations/monitor screens are present.
 
3.  STIG ID: IS-08.03.01.  This requirement is specifically focused on checking written policy/procedures and initial/recurring training concerning cleared employee responsibilities and actions to protect classified work stations (monitor screens) under their control from unauthorized viewing.  This requirement includes positioning and control of classified monitors and covers environments where  Foreign Nationals are present and US Only work stations/monitor screens are present.'
end
