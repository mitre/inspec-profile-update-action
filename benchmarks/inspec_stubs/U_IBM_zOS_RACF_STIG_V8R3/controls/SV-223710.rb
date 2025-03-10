control 'SV-223710' do
  title 'The IBM RACF database must be on a separate physical volume from its backup and recovery datasets.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', "Execute the RACDST report from DSMON Utility using 'RACF PRIMARY' and 'RACF BACKUP' as selection criteria.

If the security database and its backup exist on the same volume, this is a finding."
  desc 'fix', 'Identify the ACP database(s), backup database(s), and recovery data set(s). Develop a plan to keep these data sets on different physical volumes. Implement the movement of these critical ACP files.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25383r514818_chk'
  tag severity: 'medium'
  tag gid: 'V-223710'
  tag rid: 'SV-223710r604139_rule'
  tag stig_id: 'RACF-ES-000630'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25371r514819_fix'
  tag 'documentable'
  tag legacy: ['V-98127', 'SV-107231']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
