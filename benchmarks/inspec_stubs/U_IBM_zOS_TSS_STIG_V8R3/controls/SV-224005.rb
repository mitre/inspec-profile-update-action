control 'SV-224005' do
  title 'The CA-TSS database must be backed up on a scheduled basis.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.

Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'Refer to the TSS Proclib PARMFILE DD to determine the PARM member.

If the BACKUP is missing or coded with blank or OFF this is a finding. 

Note: If the security data base is shared only one of the systems is required to configure the BACKUP option in the PARMFILE. Determine that the option is properly coded on one of the systems that share the security database.

From the ISPF Command Shell enter:
TSS MODIFY(Status)

If the backup parameter is active with a valid time this is not a finding.'
  desc 'fix', 'Configure the TSS PARMLIB BACKUP parameter to include BACKUP statement with a valid time. Additionally, configure the BACKUP parameter in the TSS Parmfile to include BACKUP statement with a valid time for nightly backups.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25678r516414_chk'
  tag severity: 'medium'
  tag gid: 'V-224005'
  tag rid: 'SV-224005r561402_rule'
  tag stig_id: 'TSS0-OS-000090'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25666r516415_fix'
  tag 'documentable'
  tag legacy: ['V-98717', 'SV-107821']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
