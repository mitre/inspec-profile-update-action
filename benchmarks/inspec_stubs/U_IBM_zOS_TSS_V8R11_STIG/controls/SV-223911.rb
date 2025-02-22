control 'SV-223911' do
  title 'CA-TSS WRITE or Greater access to System backup files must be limited to system programmers and/or batch jobs that perform DASD backups.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Collect from the storage management group the identification of the DASD backup files and all associated storage management ACIDs.

If ESM data set rules for system DASD backup files do not restrict WRITE or greater access to z/OS systems programming and/or batch jobs that perform DASD backups this is a finding.

If  READ Access to system backup data sets is not limited to auditors and others approved by the ISSM this is a finding.'
  desc 'fix', "Obtain the high level indexes to backup data sets names define their access to be restricted by the System's ESM to System Programmers and batch jobs that perform the backups. Define READ Access to system backup data sets to be limited to auditors and others approved by the ISSM."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25584r516132_chk'
  tag severity: 'medium'
  tag gid: 'V-223911'
  tag rid: 'SV-223911r877752_rule'
  tag stig_id: 'TSS0-ES-000380'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25572r516133_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107633', 'V-98529']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
