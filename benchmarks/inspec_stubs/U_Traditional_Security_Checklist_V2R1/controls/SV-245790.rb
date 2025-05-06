control 'SV-245790' do
  title 'Information Assurance - Network Connections - Physical Protection of Unclassified (NIPRNet) Network Devices such as Routers, Switches and Hubs'
  desc 'Unclassified (NIPRNet) network connections that are not properly protected in their physical environment are highly vulnerable to unauthorized access, resulting in the probable loss or compromise of sensitive information such as personally identifiable information (PII) or For Official Use Only (FOUO).

REFERENCES:

Network Infrastructure Security Technical Implementation Guide (STIG)

Access Control in Support of Information Systems Security STIG (Access Control STIG)

CJCSI 6510.01F, INFORMATION ASSURANCE (IA) AND SUPPORT TO COMPUTER NETWORK DEFENSE (CND), Encl C, paragraph 34.

NIST Special Publication 800-53 (SP 800-53), Rev 4, Controls: 
AC-5, SC-7 (14)&(15), SC-8, SC-14, SC-32, PE-2(1), PE-3(1) & (4), PE-4 & PE-18

DoD Manual 5200.01, Volume 4, SUBJECT: DoD Information Security Program: Controlled Unclassified Information (CUI)

DoD Manual 5200.01, Volume 3, SUBJECT: DoD Information Security Program: Protection of Classified Information, Encl 7

DoD 5200.22-M (NISPOM), Incorporating Change 2, 18 May 2016, Chapter 8, paragraph 8-302.b. Physical and Environmental Protection.
 
DoD Instruction 8510.01, SUBJECT: Risk Management Framework (RMF) for DoD Information Technology (IT)

DoD Instruction 8500.01, SUBJECT: Cybersecurity

CJCSI 6211.02D, DEFENSE INFORMATION SYSTEMS NETWORK (DISN) RESPONSIBILITIES'
  desc 'check', '1. Check that ALL network connections (on NIPRNet or other Unclassified Network under review) such as routers, switches, and hubs are secured in a locked communications closet/room OR secured in a locked equipment cabinet if the equipment is located in a room that is accessed by personnel other than designated network system administrators (e.g., SAs specifically designated to administer the network devices) and/or those with security management oversight (e.g., ISSM, ISSO, SM). The intent is to ensure that only Network Administrators and other (authorized) personnel are the only persons with unimpeded access to the Network Connections.

2. If other (authorized) personnel (e.g., other than assigned system/network administrators or security management) are permitted to have unimpeded access to network devices, this authorization must be approved in writing by the site commander/director or perhaps other significant staff officer with security oversight of information systems (e.g., J6, ISSM). The documentation must include a justification indicating why the unimpeded/unescorted access is mission essential. This access allowance must be limited to very few personnel and not provided for mere convenience.

3. Ensure the locked room or cabinet cannot be easily accessed without forcible entry. Also ensure that proper key control procedures are used for ALL keys associated with both communication room doors and/or equipment cabinet doors. 

4. ANY discrepancies with the above guidelines will result in a finding.

TACTICAL ENVIRONMENT: The check is applicable for fixed tactical processing environments.  It is assumed the type of equipment referenced will be in a fixed environment.  Not applicable to a field/mobile environment.'
  desc 'fix', '1. All network connections (on NIPRNet or other Unclassified Network under review) such as routers, switches, and hubs must be secured within a locked communications closet/room OR secured within a cabinet if the equipment is located in a room that is accessed by personnel other than designated network system administrators (e.g., SAs specifically designated to administer the network devices) and/or those with security management oversight (e.g., ISSM, ISSO, SM).

2. If other (authorized) personnel (e.g., other than assigned system/network administrators or security management) are permitted to have unimpeded access to network devices, this authorization must be approved in writing by the site commander/director or perhaps other significant staff officer with security oversight of information systems (e.g., J6, ISSM). The documentation must include a justification indicating why the unimpeded/unescorted access is mission essential. This access allowance must be limited to very few personnel and not provided for mere convenience. 

3. The locked room or cabinet must be adequately secured so that it cannot be easily accessed without forcible entry. 

4. Proper key control procedures must be in place for associated keys used to secure doors to communications rooms AND equipment cabinets. 

NOTE: Because locks and keys to equipment cabinets are often inferior and do not provide for adequate physical protection it is recommended that a metal hasp be attached (using rivets or other means that cannot be removed without evidence of forcible entry) to equipment cabinets securing network equipment. General Services Administration (GSA) Medium Security Keyed Padlocks or (preferably) the S&G 8077 Changeable Combination Padlock should then be used to secure the cabinet using the hasp.'
  impact 0.5
  ref 'DPMS Target Traditional Security Checklist'
  tag check_id: 'C-49221r770030_chk'
  tag severity: 'medium'
  tag gid: 'V-245790'
  tag rid: 'SV-245790r770032_rule'
  tag stig_id: 'IA-12.02.01'
  tag gtitle: 'IA-12.02.01'
  tag fix_id: 'F-49176r770031_fix'
  tag 'documentable'
  tag legacy: ['V-31190', 'SV-41372r3_rule']
end
