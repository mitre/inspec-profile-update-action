control 'SV-224051' do
  title 'IBM z/OS DFSMS control data sets must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'Refer to the logical parmlib data sets, example: SYS1.PARMLIB(IGDSMSxx), to identify the fully qualified file names for the following SMS data sets:

Source Control Data Set (SCDS)
Active Control Data Set (ACDS)
Communications Data Set (COMMDS)
Automatic Class Selection Routine Source Data Sets (ACS)
ACDS Backup
COMMDS Backup

If the TSS data set rules for the SCDS, ACDS, COMMDS, and ACS data sets restrict UPDATE and ALL access to only systems programming personnel, this is not a finding.

If the TSS data set rules for the SCDS, ACDS, COMMDS, and ACS data sets do not restrict UPDATE and ALL access to only systems programming personnel, this is a finding.

Note: At the discretion of the ISSM, DASD administrators are allowed UPDATE access to the control data sets.'
  desc 'fix', 'Review the logical parmlib data sets, example: SYS1.PARMLIB(IGDSMSxx), to identify the fully qualified file names for the following SMS data sets:

Source Control Data Set (SCDS)
Active Control Data Set (ACDS)
Communications Data Set (COMMDS)
Automatic Class Selection Routine Source Data Sets (ACS)
ACDS Backup
COMMDS Backup

Assign ownership of the data sets, replacing user-id with a user, department, or division that administer access to the SMS control data sets, and data name with the prefix of the SMS control data sets:

TSS ADD(user-id) DSN(data name)

Ensure the TSS data set rules for the SCDS, ACDS, COMMDS, and ACS data sets restrict UPDATE and ALL access to only z/OS systems programming personnel.

Note: At the discretion of the ISSM, DASD administrators are allowed UPDATE access to the control data sets.

Permit access to those personnel who manage the SMS environment, replacing user-id with the userid of the user or a Group profile:

TSS PERMIT(user-id) DSN(data name) ACC(UPDATE) ACTION(AUDIT)

Permit access to those personnel that perform maintenance on these data sets:

TSS PERMIT(user-id) DSN(data name) ACC(ALL) ACTION(AUDIT)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25724r516552_chk'
  tag severity: 'medium'
  tag gid: 'V-224051'
  tag rid: 'SV-224051r561402_rule'
  tag stig_id: 'TSS0-SM-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25712r516553_fix'
  tag 'documentable'
  tag legacy: ['SV-107913', 'V-98809']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
