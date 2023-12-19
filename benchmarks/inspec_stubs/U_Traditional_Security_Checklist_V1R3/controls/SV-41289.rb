control 'SV-41289' do
  title 'Information Assurance - Network Connections - Physical Protection of Network Devices such as Routers, Switches and Hubs (Connected to SIPRNet or Other Classified Networks or Systems Being Inspected)'
  desc 'SIPRNet or other classified network connections that are not properly protected in their physical environment are highly vulnerable to unauthorized access, resulting in the probable loss or compromise of classified or sensitive information.

REFERENCES:

Network Infrastructure Security Technical Implementation Guide (STIG)

Access Control in Support of Information Systems Security STIG (Access Control STIG)

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraph 34.c.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
AC-5, SC-7 (14)&(15), SC-8, SC-14, SC-32, PE-2(1), PE-3(1) & (4), PE-4 & PE-18

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 3, Appendix to Encl 3, and Encl 7

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraph 8-302.b. Physical and Environmental Protection. 
 
DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT)

DoD Instruction 8500.01, SUBJECT: Cybersecurity

CJCSI 6211.02D, DEFENSE INFORMATION SYSTEMS NETWORK (DISN) RESPONSIBILITIES,

CNSSP No.29, May 2013, National Secret Enclave Connection Policy'
  desc 'check', 'CHECK 1. Check to ensure that network devices on a Classified Network (SIPRNet) such as routers, switches, and hubs are housed within an approved classified storage safe, vault, or approved open storage area (AKA: secure room), or a SCIF. (CAT I)

Two alternatives exist for check #1 in lieu of storage in a classified (secret or higher) vault, secure room or a SCIF:

a. Information Processing System (IPS) containers are safes designed to house operational Information Systems (IS) equipment and can be used to meet this requirement. The use of an IPS container is often a good recommendation when a deficiency is found.

b. A second alternative is to house network equipment in a 24/7 continuously occupied room or area. When using this method of control the equipment must be under the continuous (physical) observation and control of the cleared occupants. If using this alternative the network equipment must be maintained in lockable equipment storage cabinets. This is to ensure that only Network Administrators and other (authorized) personnel are the only persons with unimpeded access to the Network Connections. If the equipment is under continuous observation and control but not in a lockable cabinet or otherwise maintained to ensure that only Network Administrators and other(authorized) personnel have access, then it will be a CAT II finding under check #2 below. 

CHECK 2. Check also to ensure that only Network Administrators and other (authorized) personnel are the only persons with unimpeded access to the Network Connections, regardless if properly housed in a safe, vault or secure room (AKA: collateral classified open storage area). Lockable equipment storage cabinets may be used to meet this requirement (but only when the storage cabinets housing the network equipment is located within a vault, secure room or SCIF). (CAT II) 

CHECK 3. If other (authorized) personnel (e.g., other than assigned system/network administrators) are permitted to have unimpeded access to network devices, this authorization must be approved in writing by the site commander/director or perhaps other significant staff officer with security oversight of information systems (e.g., J6, ISSM). The documentation must include a justification indicating why the unimpeded/unescorted access is mission essential. This access allowance must be limited to very few personnel and not provided for mere convenience. (CAT II)

TACTICAL ENVIRONMENT: The check is applicable for fixed tactical classified processing environments. It is assumed the type of equipment referenced will be in a fixed environment. Not applicable to a field/mobile environment.'
  desc 'fix', '1. Network devices on a Classified Network (SIPRNet) such as routers, switches, and hubs must be housed within an approved classified storage safe, vault, or approved open storage area (AKA: secure room, or in a SCIF.  Information Processing System (IPS) containers are safes designed to house operational Information System (IS) equipment and can be used to meet this requirement. 

2. An alternative to housing classified network devices in approved storage containers or areas is they must be housed in a 24/7 continuously occupied room or area.  Occupants of the room or area must possess a security clearance equal to or greater than the level of the classified network devices. 

3. Network Administrators and other (authorized) personnel must be the only persons with unimpeded access to the SIPRNet Network devices, regardless if properly housed in an approved safe, vault, secure room (AKA: collateral classified open storage area),in a SCIF, or in a 24/7 continuously occupied room or area. Lockable equipment storage cabinets may be used to meet this requirement (when network devices are housed within a vault, secure room or SCIF). 

4. If other (authorized) personnel (e.g., other than assigned system/network administrators) are permitted to have unimpeded access to network devices, this authorization must be approved in writing by the site commander/director or perhaps other significant staff officer with security oversight of information systems (e.g., J6, ISSM).  The documentation must include a justification indicating why the unimpeded/unescorted access is mission essential. This access allowance must be limited to very few personnel and not provided for mere convenience.'
  impact 0.7
  ref 'DPMS Target Traditional Security'
  tag check_id: 'C-39902r15_chk'
  tag severity: 'high'
  tag gid: 'V-31132'
  tag rid: 'SV-41289r3_rule'
  tag stig_id: 'IA-12.01.01'
  tag gtitle: 'Information Assurance - Network Connections - Physical Protection of SIPRNet Network Devices'
  tag fix_id: 'F-35081r7_fix'
  tag 'documentable'
  tag severity_override_guidance: 'CAT I is the default severity level for when SIPRNet network connections/equipment is found not to be properly protected in a proper safe, vault, secure room, SCIF or under continuous observation and control.

CAT II severity level may be assigned when the equipment is properly housed in an area or container  approved for classified storage or under continuous observation and control of a properly cleared employee; however, persons other than the Network Administrators and other (authorized) personnel have unimpeded access to the Network Connections,.

CAT II severity level may also be assigned when documentation does not exist to justify unimpeded access to network equipment by other (authorized) personnel (e.g., other than assigned network/system administrators).  Documentation must be signed by the site commander/director or J6/ISSM primary staff officer with responsibility for oversight of security on information systems AND provide mission essential justification for allowing unimpeded/unescorted access.'
end
