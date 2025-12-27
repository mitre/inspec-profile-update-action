control 'SV-16785' do
  title 'Auditing is not configured on the ESX Server.'
  desc 'Audit utilities can extract information about specific users and processes from the audit files. The IAO/SA will ensure audit files are only accessible to authorized personnel. Auditing will be configured to immediately alert personnel of any unusual or inappropriate activity with potential IA implications. All users, including root, will be audited. The system administrator will rotate and compress the audit logs one or more times a day to reduce space and the time required for log searches and reviews. Audit data will be backed up weekly onto a different system or media than the system being audited. Utilizing an audit server will ease the attention required by audit logs and provide compliance with the requirement for the backup of audit data.

Auditing will be configured according to section 3.16 of the UNIX STIG.  Audit logs and audit files must be analyzed at regular intervals. Such files can quickly grow to large proportions. To keep the size of log files and audit files within a useful range, the evaluation intervals should not be impractically short, but short enough to allow a clear examination.  Collected data will be examined and analyzed daily to detect any compromise or attempted compromise of system security.'
  desc 'check', 'On the ESX Server service console perform the following command:

#ps –ef | grep auditd

Verify the auditd daemon is running.  If it is not, this is a finding.'
  desc 'fix', 'Configure LAUS on the ESX Server.  LAUS is included on the ESX distribution media. The procedures to install it are as follows:
laus-libs-0.1-76RHEL3.i386.rpm is installed, but laus-0.1-76RHEL3.i386.rpm is not.
1. Mount the ISO image / CD-ROM to VMware/RPMS, and install via # rpm -ivh laus-    0.1-76RHEL3.i386.rpm 
2. Run the following command from the shell # service audit start
3. Run the following commands to test to see if LAUS is configured.  These commands will produce output: # /usr/sbin/aucat OR # /usr/sbin/augrep.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16192r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15844'
  tag rid: 'SV-16785r1_rule'
  tag stig_id: 'ESX0450'
  tag gtitle: 'Auditing is not configured on the ESX Server.'
  tag fix_id: 'F-15798r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
