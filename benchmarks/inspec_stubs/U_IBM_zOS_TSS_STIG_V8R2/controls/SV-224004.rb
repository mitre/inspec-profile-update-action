control 'SV-224004' do
  title 'The CA-TSS database must be on a separate physical volume from its backup and recovery data sets.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Refer to the System proclibs for the TSS STC. 

If the Security database is located on the same volume as either the backup, Alternate or Recovery file, this is a finding.'
  desc 'fix', 'Configure the placement of ESM files are on a separate volume from its backup and recovery data sets to provide backup and recovery in the event of physical damage to a volume.

Identify the ESM database(s), backup database(s), and recovery data set(s). Develop a plan to keep these data sets on different physical volumes. Implement the movement of these critical ESM files.

File location is an often overlooked factor in system integrity. It is important to ensure that the effects of hardware failures on system integrity and availability are minimized. Avoid collocation of files such as primary and alternate databases. For example, the loss of the physical volume containing the ESM database should not also cause the loss of the ESM backup database as a result of their collocation. Files that will be segregated from each other on separate physical volumes include, but are not limited to, the ESM database and its alternate or backup file.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25677r516411_chk'
  tag severity: 'medium'
  tag gid: 'V-224004'
  tag rid: 'SV-224004r561402_rule'
  tag stig_id: 'TSS0-OS-000080'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25665r516412_fix'
  tag 'documentable'
  tag legacy: ['V-98715', 'SV-107819']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
