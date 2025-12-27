control 'SV-223709' do
  title 'IBM RACF use of the AUDITOR privilege must be justified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
ListUser *

If authorization to the SYSTEM AUDITOR attribute is restricted to auditing and/or security personnel, this is not a finding.

If at minimum, any users connected to sensitive system dataset HLQ (e.g., SYS1, SYS2, etc.) groups or general resource owning groups with the Group-AUDITOR attribute are Auditor and/or Security personnel, this is not a finding.

Otherwise, Group-AUDITOR is allowed.'
  desc 'fix', 'Review all USERIDs with the AU (Manual) - Review all USERIDs with the AUDITOR attribute. Ensure documentation providing justification for access is maintained and filed with the ISSO, and that unjustified access is removed.

The AUDITOR attribute is removed from a user with the command: ALU <userid> NOAUDITOR.

To remove the Group-Auditor attribute:

CO <user> GROUP(<groupname>) NOAUDITOR'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25382r514815_chk'
  tag severity: 'medium'
  tag gid: 'V-223709'
  tag rid: 'SV-223709r604139_rule'
  tag stig_id: 'RACF-ES-000620'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25370r514816_fix'
  tag 'documentable'
  tag legacy: ['V-98125', 'SV-107229']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
