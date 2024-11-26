control 'SV-223976' do
  title 'IBM z/OS data sets for the FTP server must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'If WRITE and ALLOCATE access to the data set containing the FTP Data configuration file is restricted to systems programming personnel this is not a finding.

Note: READ access to all authenticated users is permitted.

If WRITE and ALLOCATE access to the data set containing the FTP Data configuration file is logged this is not a finding.

If WRITE and ALLOCATE access to the data set containing the FTP banner file is restricted to systems programming personnel this is not a finding.

Note: READ access to the data set containing the FTP banner file is permitted to all authenticated users.

Notes: The MVS data sets mentioned above are not used in every configuration. Absence of a data set will not be considered a finding.
The data set containing the FTP Data configuration file is determined by checking the SYSFTPD DD statement in the FTP started task JCL.
The data set containing the FTP banner file is determined by checking the BANNER statement in the FTP Data configuration file.'
  desc 'fix', 'Review the data set access authorizations defined to the ACP for the FTP.DATA and FTP.BANNER files. Configure these data sets to be protected as follows:'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25649r516327_chk'
  tag severity: 'medium'
  tag gid: 'V-223976'
  tag rid: 'SV-223976r561402_rule'
  tag stig_id: 'TSS0-FT-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25637r516328_fix'
  tag 'documentable'
  tag legacy: ['SV-107763', 'V-98659']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
