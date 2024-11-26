control 'SV-223816' do
  title 'IBM z/OS DFSMS control data sets must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Review the logical parmlib data sets, example: SYS1.PARMLIB(IGDSMSxx), to identify the fully qualified file names for the following SMS data sets:

Source Control Data Set (SCDS)
Active Control Data Set (ACDS)
Communications Data Set (COMMDS)
Automatic Class Selection Routine Source Data Sets (ACS)
ACDS Backup
COMMDS Backup

If the RACF data set rules for the SCDS, ACDS, COMMDS, and ACS data sets restrict WRITE or greater access to only systems programming personnel, this is not a finding.

If the RACF data set rules for the SCDS, ACDS, COMMDS, and ACS data sets do not restrict WRITE or greater access to only systems programming personnel, this is a finding.

Note: At the discretion of the ISSM, DASD administrators are allowed UPDATE access to the control datasets.'
  desc 'fix', "Review the SYS1.PARMLIB(IGDSMS00) data set to identify the fully qualified file names for the following SMS data sets:

Source Control Data Set (SCDS)
Active Control Data Set (ACDS)
Communications Data Set (COMMDS)
Automatic Class Selection Routine Source Data Sets (ACS)
ACDS Backup
COMMDS Backup

Configure the RACF data set rules for the SCDS, ACDS, COMMDS, and ACS data sets to restrict WRITE or greater access to only z/OS systems programming personnel.

Note: At the discretion of the ISSM, DASD administrators are allowed UPDATE access to the control datasets.

Some example commands to implement the proper controls are shown here:

AD 'sys3.dfsms.mmd.commds.**' UACC(NONE) OWNER(SYS3) AUDIT(ALL(READ)) DATA('PROTECTED PER ZSMS0020')

PE 'sys3.dfsms.mmd.commds.**' ID(<syspsmpl>) ACC(A)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25489r515136_chk'
  tag severity: 'medium'
  tag gid: 'V-223816'
  tag rid: 'SV-223816r604139_rule'
  tag stig_id: 'RACF-SM-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25477r515137_fix'
  tag 'documentable'
  tag legacy: ['V-98339', 'SV-107443']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
