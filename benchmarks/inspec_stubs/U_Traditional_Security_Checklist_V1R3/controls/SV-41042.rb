control 'SV-41042' do
  title 'Information Assurance - System Security Operating Procedures (SOPs)'
  desc 'Failure to have documented procedures in an SOP could result in a security incident due to lack of knowledge by personnel assigned to the organization.

REFERENCES:

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND)

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
PL-1, PL-2 and PL-4

DoDI 8500.01, SUBJECT: Cybersecurity, March 14, 2014

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information,, Encl 5, para 3.a.(4), 3.d., 7.a. ; Encl 7, para 5.c., 6, 10, and 11.

DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT)

United States Cyber Command Instruction (USCCI) 5200-13, 13 April 2019, SUBJECT: Cyberspace Protection Conditions (CPCON)'
  desc 'check', 'Check written SOPs covering all systems, supporting infrastructure and physical facilities. Conduct a cursory review of the SOPs and as a minimum ensure the following areas are documented:

a. Handling of suspected system compromise or spillage
b. Cyberspace Protection Conditions (CPCON) - formerly Information Operations Condition (INFOCON) - procedures and policies
c. Procedures for eradication after an attack
d. Proper password management
e. Purging of storage media (disks, CDs, DVDs, drives, etc.) prior to turn-in or disposal
f. Remote diagnostic and maintenance approval and procedure 
g. Out-processing and turn-in of equipment
h. Use of screensavers/Unattended terminals
i. Virus detection and scanning
j. In-processing and vetting of employees for systems access (proper investigation and security clearance)                                                                         
NOTE: This requirement for on-hand SOPs should not be applied to a tactical environment, unless it is a fixed computer facility in a Theater of Operations.  The standards to be applied for applicability in a tactical environment are:

1) The facility containing the computer room has been in operation over 1-year. 
2) The facility is "fixed facility" - a hard building made from normal construction materials - wood, steel, brick, stone, mortar, etc. 
3) Procedures for field/mobile elements are still required and should be available at a supporting headquarters, either in Theater or perhaps even CONUS. These may be requested during pre-trip coordination or obtained after visiting the tactical AO.'
  desc 'fix', '1. Security Operating Procedures (SOPs) covering all systems, supporting infrastructure and physical facilities must be written.

2. The procedures must be readily available to both the Information Assurance Staff (ISSM, ISSO, SA) and all system users requiring information in the procedures to perform their jobs. Information can be placed in an Information System Users Guide (SFUG) and other applicable documents as appropriate. SOP availability must be on a site intranet, shared folders, WEB page, etc. for ease of reference by all employees - unless classified or otherwise requiring restricted access.

As a minimum the following areas must be documented:

a. Handling of suspected system compromise or spillage
b. Cyberspace Protection Conditions (CPCON) - formerly Information Operations Condition (INFOCON) - procedures and policies
c. Procedures for eradication after an attack
d. Proper password management
e. Purging of storage media (disks, CDs, DVDs, drives, etc.) prior to turn-in or disposal
f. Remote diagnostic and maintenance approval and procedure 
g. Out-processing and turn-in of equipment
h. Use of screensavers/Unattended terminals
i. Virus detection and scanning
j. In-processing and vetting of employees for systems access (proper investigation and security clearance)'
  impact 0.3
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39663r10_chk'
  tag severity: 'low'
  tag gid: 'V-30996'
  tag rid: 'SV-41042r3_rule'
  tag stig_id: 'IA-01.03.01'
  tag gtitle: 'Information Assurance - System Security SOPs'
  tag fix_id: 'F-34809r12_fix'
  tag 'documentable'
end
