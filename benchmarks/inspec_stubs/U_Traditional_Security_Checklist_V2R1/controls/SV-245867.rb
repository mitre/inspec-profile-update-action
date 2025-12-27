control 'SV-245867' do
  title 'Security-in-Depth (AKA: Defense-in-Depth) - Minimum Physical Barriers and Access Control Measures for Facilities or Buildings Containing DoDIN (SIPRNet/NIPRNet) Connected Assets.'
  desc 'Failure to use security-in-depth can result in a facility being vulnerable to an undetected intrusion or an intrusion that cannot be responded to in a timely manner - or both.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Enclosure A, paragraph 5.a.(1).

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: PE-2(2), PE-3, PE-6(1), and page B-6: Security-in-Depth defined.

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014 , Enclosure 2, paragraph 13.s. and  Enclosure 3, paragraph 7.                                    

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information: Enclosure 2 paragraph 12.; Enclosure 3, paragraph 3.b.(3) & paragraph 4.; Enclosure 7, paragraph 7.d.; and Glossary page 121, Security-in-Depth defined.

DoD 5200.22-M (NISPOM), February 2006, Incorporating Change 2, May 18, 2016
Chapter 5, paragraphs 5-303, 5-307 & 5-904.b. and Appendix C, Definitions, page C-6 - Security in Depth.

DoD 5200.8-R Physical Security Program, April 9, 2007, Incorporating Change 1, May 27, 2009:  Chapter 2, C2.3.1, C3.2.1 and DL1.17., Security-in-Depth defined.

CNSSI No.7003, September 2015, Protected Distribution Systems (PDS), Section IV, paragraph 6, Section VIII, Table 1 and Table 2, and Section VI - DEFINITIONS - Controlled Access Area (CAA).'
  desc 'check', 'Background Information:  This set of checks is intended to validate security-in-depth protection measures in place for facilities with either Unclassified DoDIN assets (NIPRNet) or Classified (SIPRNet) DoDIN assets or both.  Checks are specifically oriented to each (one or more) of the following 4-situations:

1.  Protection of unclassified (NIPRNet) assets (such as-end user workstations with typical office equipment - PC/laptop/thin client/multi-functional devices (MFD), printers, copiers, scanners, facsimile machine...) that are housed and operated in administrative office spaces.

2.  Protection of unclassified (NIPRNet) assets housed and operated in unclassified computer rooms.  This check is intended for rooms with key system assets such as servers, routers, DASD, etc., rather than end user workstations.  This high level system equipment requires an additional layer of physical protection and access control.

3.  Protection of classified (SIPRNet) assets (such as end-user workstations with typical office equipment - PC/laptop/thin client/multi-functional devices (MFD), printers, copiers, scanners, facsimile machine...) that are housed and operated in administrative office spaces NOT designated for collateral classified open storage (AKA: secure room or closed storage area).  Normally such space should be controlled/designated as secret controlled access areas (CAA) for SIPRNet.

4.  Protection of classified (SIPRNet) assets housed and operated in space designated for collateral classified open storage (AKA: secure room or closed storage area).  Assets in this situation may include both end-user workstations with typical office equipment as detailed above and/or Computer Rooms containing key system assets such as servers, routers, DASD, etc.  So to restate, this includes any classified equipment (both end-user and key system equipment) stored and operated in space designated for and meeting collateral classified open storage standards.
Where both NIPRNet and SIPRNet assets as well as end-user and system level assets are co-located in a facility - the most stringent SID standards applicable for the area will be used.

Checks:

1. Protection of areas containing unclassified (NIPRNet) assets (such as end user workstations):
Check that any facility (building, room or area) housing  unclassified information system assets connected to the DODIN (such as end user NIPRNet work stations) has at least one physical barrier supplemented by any type of 24/7 access control (keyed locks, reception, guards, Access Control System, Cipher Locks, etc.).

2.  Protection of unclassified (NIPRNet) assets housed and operated in unclassified computer rooms:

Check to ensure that Unclassified Computer Rooms containing equipment connected to the DoDIN (located within a facility (building, room or area) meeting the standard in #1 above) have an additional layer of physical protection and access control (beyond that for the surrounding facility or area). This check is intended for rooms with key system assets such as servers, routers, etc., rather than end user workstations.  

3.  Protection of classified (SIPRNet) assets (such as end user workstations with typical office equipment that are NOT housed and operated within a facility designated as a collateral classified open storage area):

    a.  Check to ensure that every physical access point to facilities housing DoDIN end-user workstations that process or display classified information is guarded or alarmed 24/7 (minimum of alarm contacts on the doors) and that intrusion alarms are properly monitored.  This is space NOT designated as a collateral classified open storage area.  Normally such space should be access controlled/designated as a secret controlled access area (CAA) for SIPRNet.

    b.  Check that two forms of identification are required to gain access to a facility housing DoDIN workstations that process or display classified information (e.g., key card with PIN/biometrics or two acceptable forms of picture ID presented to a guard or receptionist).
 
    c.  Check to ensure that a visitor log is maintained for facilities containing DoDIN end-user workstations that process or display classified information. Automated Entry Control System (AECS) log entries may be used to meet this requirement.

NOTE:  Physical access points to facilities housing DoDIN workstations in secret CAAs that process or display classified information, which are located on an access controlled military installation (or that employ another layer of physical barrier/access control) are not required to have an IDS alarm contact on the doors and need only one level of access control.  For instance access control to the facility using only a swipe or proximity card (w/o PIN or biometrics) or a guard checking a single picture ID is acceptable.

4.  Protection of classified (SIPRNet) assets housed and operated in space designated for collateral classified open storage (AKA: secure room or closed storage area):

*Check to ensure that the senior agency official (SAO) has determined in writing that security-in-depth (SID) exists.

Note that the SAO for the Defense Security Service (DSS)/industry is the Cognizant Security Agency (CSA)/Cognizant Security Office (CSO).

SID Explained:
 
SID is a determination that the security program consists of layered and complementary security controls sufficient to deter and detect unauthorized entry and movement within the facility. Examples include, but are not limited to, use of perimeter fences, employee and visitor access controls, use of an IDS, random guard patrols throughout the facility during non-working hours, closed circuit video monitoring or other safeguards that mitigate the vulnerability of open storage areas without alarms as well as for security containers (safes) during non-working hours.
  
Specific Secure Room security standards are not covered under this check for security-in-depth as they are covered in other Rules within this STIG. 
 
Selection of supplementary controls for secure rooms (IDS versus 4-hours guard checks) is based upon the SID in conjunction with an assessment of risk that is accepted by the SAO.
  
Access control requirements for collateral open storage areas are established and must be IAW the DoD Manual 5200.01, V3 and as implemented by Rules in this STIG.

An SID determination may be rendered using one of two methods:
  
First, the SAO can issue SID approvals on a case-by-case basis.  For instance the facility or organization with collateral open storage space would provide the SAO with a request for SID (IAW pre-established organizational (CC/S/A) procedures) that is subsequently approved or disapproved by the SAO.
  
A second method would be for the CC/S/A to establish a policy (Manual, Instruction, Regulation, Circular, etc.) that provides specific criteria or requirements that when met by organizations is evidence of adequate SID for collateral open storage spaces.  Criteria may be based on additional considerations such threat environments (high, medium, or low), if the space is on access controlled installations versus off-installations in public accessible space, CONUS versus OCONUS sites or other such considerations per the discretion of the SAO of the CC/S/A.
  
Regardless of the method used by the SAO to render an SID determination, it must be properly documented and clearly apply to the collateral open storage area (AKA: secure room or closed storage area) being evaluated.

TACTICAL ENVIRONMENT: The check is applicable for fixed (established) tactical processing environments.  Not applicable to a field/mobile environment.'
  desc 'fix', 'Background Information:  This standard is intended to validate security-in-depth protection measures in place for facilities containing either unclassified DoDIN assets (NIPRNet) or classified (SIPRNet) DoDIN assets or both.  The first two fixes are specifically for unclassified DoDIN facilities, while fixes 3 and 4 are for facilities containing SIPRNet assets.  Where both NIPRNet and SIPRNet assets are contained in a facility - the more stringent standards for SIPRNet will be used.

Fixes:

1. Ensure that any facility/building housing unclassified information system assets connected to the DoDIN (such as end-user NIPRNet work stations) has at least one physical barrier supplemented by any type of 24/7 access control (keyed locks, reception, guards, Access Control System, Cipher Locks, etc.).

2. Ensure that unclassified Computer Rooms containing equipment connected to the DoDIN (located within a facility (building, room or area) meeting the standard in #1 above) have an additional layer of physical protection and access control. This fix is intended for rooms with key system assets such as servers, routers, DASD, etc., rather than end user workstations.  

3.  Protection of classified (SIPRNet) assets (such as end user workstations with typical office equipment that are NOT housed and operated within a facility designated as a collateral classified open storage area):

    a.  Ensure that every physical access point to facilities housing DoDIN end-user workstations that process or display classified information is guarded or alarmed 24/7 (minimum of alarm contacts on the doors) and that intrusion alarms are properly monitored.  This is space NOT designated as a collateral classified open storage area.  Normally such space should be controlled/designated as a secret controlled access area (CAA) for SIPRNet.

    b.  Ensure that two forms of identification are required to gain access to a facility housing DoDIN workstations that process or display classified information (e.g., key card with PIN/biometrics or two acceptable forms of picture ID presented to a guard or receptionist). 

    c.  Ensure that a visitor log is maintained for facilities containing DoDIN end-user workstations that process or display classified information. Automated Entry Control System (AECS) log entries may be used to meet this requirement.

NOTE:  Physical access points to facilities housing DoDIN workstations in secret CAAs that process or display classified information, which are located on an access controlled military installation (or that employ another layer of physical barrier/access control) are not required to have an IDS alarm contact on the doors and need only one level of access control.  For instance access control to the facility using only a swipe or proximity card (w/o PIN or biometrics) or a guard checking a single picture ID is acceptable.

4.  Where there are Information System assets stored in secure rooms (AKA: collateral classified open storage areas) that are connected to the SIPRNet - ensure that the senior agency official has determined in writing that security-in-depth exists. 

*Note that the SAO for the Defense Security Service (DSS)/industry is the Cognizant Security Agency (CSA)/Cognizant Security Office (CSO).'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49298r770261_chk'
  tag severity: 'medium'
  tag gid: 'V-245867'
  tag rid: 'SV-245867r770263_rule'
  tag stig_id: 'PH-05.02.01'
  tag gtitle: 'PH-05.02.01'
  tag fix_id: 'F-49253r770262_fix'
  tag 'documentable'
  tag legacy: ['V-32601', 'SV-42938r3_rule']
end
