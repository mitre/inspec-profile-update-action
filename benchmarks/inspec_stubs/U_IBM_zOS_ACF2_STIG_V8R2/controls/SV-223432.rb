control 'SV-223432' do
  title 'CA-ACF2 must limit update and allocate access to system backup files to system programmers and/or batch jobs that perform DASD backups.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Execute a data set list of access for SMF data collection files (e.g., SYS1.MAN* or IFASMF.SYS1.*). 

If the ESM data set rules for the SMF data collection files do not restrict ALTER access to only z/OS systems programming personnel, this is a finding.'
  desc 'fix', 'Configure the update and allocate access to libraries containing PPT modules to be limited to system programmers only and all update and allocate access is logged.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25105r500426_chk'
  tag severity: 'medium'
  tag gid: 'V-223432'
  tag rid: 'SV-223432r533198_rule'
  tag stig_id: 'ACF2-ES-000110'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25093r500427_fix'
  tag 'documentable'
  tag legacy: ['SV-106665', 'V-97561']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
