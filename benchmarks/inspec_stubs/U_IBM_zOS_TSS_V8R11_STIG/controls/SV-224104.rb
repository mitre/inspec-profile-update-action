control 'SV-224104' do
  title 'IBM z/OS System data sets used to support the VTAM network must be properly secured.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Create a list of data set names containing all VTAM start options, configuration lists, network resource definitions, commands, procedures, exit routines, all SMP/E TLIBs, and all SMP/E DLIBs used for installation and in development/production VTAM environments.
If the ESM data set rules for all VTAM system data sets restrict access to only network systems programming staff, this is not a finding. 
If RACF data set rules for all VTAM system data sets all READ access to auditors only, this is not a finding.

These data sets include libraries containing VTAM load modules and exit routines, and VTAM start options and definition statements.'
  desc 'fix', %q(Configure TSS data set rules for all VTAM system data sets restrict access to only network systems programming staff.
Auditors may have READ access as documented by and approved by the ISSM.

These data sets include libraries containing VTAM load modules and exit routines, and VTAM start options and definition statements. 

The following sample TSS commands show proper permissions for VTAM data sets (replace "profile" with the profile name of the network systems programming staff authorities): 

TSS PERMIT(profile) DSN(SYS1.VTAM.) ACC(ALL) 
TSS PERMIT(profile) DSN('SYS1.VTAMLIB.) ACC(ALL) 
TSS PERMIT(profile) DSN(SYS1.VTAM.SISTCLIB.) ACC(ALL) 
TSS PERMIT(profile) DSN(SYS3.VTAM.) ACC(ALL) 
TSS PERMIT(profile) DSN(SYS3.VTAMLIB.) ACC(ALL))
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25777r516711_chk'
  tag severity: 'medium'
  tag gid: 'V-224104'
  tag rid: 'SV-224104r877944_rule'
  tag stig_id: 'TSS0-VT-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25765r516712_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['SV-108019', 'V-98915']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
