control 'SV-223518' do
  title 'IBM z/OS data sets for the FTP Server must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer to the FTP server Started task (usually FTPD). Refer to the data set defined on the SYSFTPD DD statement.

If the WRITE and ALLOCATE access to the data set containing the FTP Data configuration file is restricted to systems programming personnel, this is not a finding.

NOTE: READ access to all authenticated users is permitted.

If WRITE and ALLOCATE access to the data set containing the FTP Data configuration file is logged, this is not a finding.

Refer to the BANNER statement in the FTP Data configuration file. If the BANNER statement refers to an MVS data set and WRITE and ALLOCATE access to the data set containing the FTP banner file is restricted to systems programming personnel, this is not a finding.

If READ access to the data set containing the FTP banner file is permitted to all authenticated users, this is not a finding.

NOTES: The MVS data sets mentioned above are not used in every configuration. Absence of a data set will not be considered a finding.'
  desc 'fix', 'Review the data set access authorizations defined to the ESM for the FTP.DATA and FTP.BANNER files. Configure these data sets to be protected as follows:

The data set containing the FTP.DATA configuration file allows read access to all authenticated users and all other access is restricted to systems programming personnel.

All write and allocate access to the data set containing the FTP.DATA configuration file is logged.

The data set containing the FTP banner file allows read access to all authenticated users and all other access is restricted to systems programming personnel.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25191r504618_chk'
  tag severity: 'medium'
  tag gid: 'V-223518'
  tag rid: 'SV-223518r533198_rule'
  tag stig_id: 'ACF2-FT-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25179r504619_fix'
  tag 'documentable'
  tag legacy: ['V-97741', 'SV-106845']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
