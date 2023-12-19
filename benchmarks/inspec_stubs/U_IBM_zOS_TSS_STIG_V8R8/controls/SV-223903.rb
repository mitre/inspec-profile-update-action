control 'SV-223903' do
  title 'CA-TSS security data sets and/or databases must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Determine all associated ESM security data sets and/or databases.

If the following accesses to the ESM security data sets and/or databases are properly restricted as detailed below, this is not a finding.

The ESM data set rules for ESM security data sets and/or databases restrict READ access to auditors and DASD batch.

The ESM data set rules for ESM security data sets and/or databases restrict READ and/or greater access to z/OS systems programming personnel, security personnel, and/or batch jobs that perform ESM maintenance.

All (i.e., failures and successes) data set access authorities (i.e., READ, UPDATE, ALTER, and CONTROL) for ESM security data sets and/or databases are logged.'
  desc 'fix', 'Review access authorization to critical security database files. Evaluate the impact of correcting the deficiency. Develop a plan of action and implement the changes required to protect the ESM files.

Configure READ and/or greater access to all ESM files and/or databases are limited to system programmers and/or security personnel, and/or batch jobs that perform ESM maintenance. READ access can be given to auditors and DASD batch. All accesses to ESM files and/or databases are logged.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25576r516108_chk'
  tag severity: 'high'
  tag gid: 'V-223903'
  tag rid: 'SV-223903r856074_rule'
  tag stig_id: 'TSS0-ES-000300'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25564r516109_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000134-GPOS-00068', 'SRG-OS-000259-GPOS-00100', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98513', 'SV-107617']
  tag cci: ['CCI-000213', 'CCI-001084', 'CCI-001499', 'CCI-002235']
  tag nist: ['AC-3', 'SC-3', 'CM-5 (6)', 'AC-6 (10)']
end
