control 'SV-223595' do
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

If the ACF2 data set rules for the SCDS, ACDS, COMMDS, and ACS data sets restrict UPDATE and ALLOCATE access to only systems programming personnel, this not is a finding.

If the ACF2 data set rules for the SCDS, ACDS, COMMDS, and ACS data sets do not restrict UPDATE and ALLOCATE access to only systems programming personnel, this is a finding.

Note: At the discretion of the ISSM, DASD administrators are allowed UPDATE access to the control data sets.'
  desc 'fix', 'Configure DFSMS control data sets to restrict UPDATE or ALLOCATE access to system programmers responsible for DASD management. Justification is required for any additional access.

Review the SYS1.PARMLIB(IGDSMSxx) data set to identify the fully qualified file names for the following SMS data sets:
Source Control Data Set (SCDS)
Active Control Data Set (ACDS)
Communications Data Set (COMMDS)
Automatic Class Selection Routine Source Data Sets (ACS)
ACDS Backup
COMMDS Backup

Define ACF2 data set rules for the SCDS, ACDS, COMMDS, and ACS data sets to restrict UPDATE and ALLOCATE access to only systems programming personnel.

Note: At the discretion of the ISSM, DASD administrators are allowed UPDATE access to the control data sets.

Example:
$KEY(S3D) 
$PREFIX(SYS3)
DFSMS.MVA.ACDS UID(uuuuuuuu) R(A) W(L) A(L) E(A)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25268r504755_chk'
  tag severity: 'medium'
  tag gid: 'V-223595'
  tag rid: 'SV-223595r533198_rule'
  tag stig_id: 'ACF2-SM-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25256r504756_fix'
  tag 'documentable'
  tag legacy: ['SV-106999', 'V-97895']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
