control 'SV-224053' do
  title 'IBM z/OS DFSMS control data sets must be properly protected.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'Review the logical parmlib data sets, example: SYS1.PARMLIB(IGDSMSxx), to identify the fully qualified file names for the following SMS data sets:

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
  tag check_id: 'C-25726r516558_chk'
  tag severity: 'medium'
  tag gid: 'V-224053'
  tag rid: 'SV-224053r877891_rule'
  tag stig_id: 'TSS0-SM-000050'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-25714r516559_fix'
  tag 'documentable'
  tag legacy: ['SV-107917', 'V-98813']
  tag cci: ['CCI-000366', 'CCI-000549']
  tag nist: ['CM-6 b', 'CP-9 (6)']
end
