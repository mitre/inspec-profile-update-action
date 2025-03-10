control 'SV-213515' do
  title 'File permissions must be configured to protect log information from unauthorized deletion.'
  desc 'If log data were to become compromised, then competent forensic analysis and discovery of the true source of potentially malicious system activity is difficult, if not impossible, to achieve.

When not configured to use a centralized logging solution like a syslog server, the JBoss EAP application server writes log data to log files that are stored on the OS, appropriate file permissions must be used to restrict deletion.

Logon formation includes all information (e.g., log records, log settings, transaction logs, and log reports) needed to successfully log information system activity. Application servers must protect log information from unauthorized deletion.'
  desc 'check', 'Examine the log file locations and inspect the file permissions.  Interview the system admin to determine log file locations. The default location for the log files is:

Standalone configuration:
<JBOSS_HOME>/standalone/log/

Managed Domain configuration:
<JBOSS_HOME>/domain/servers/<servername>/log/
<JBOSS_HOME>/domain/log/

Review the file permissions for the log file directories.  The method used for identifying file permissions will be based upon the OS the EAP server is installed on.

Identify all users with file permissions that allow them to delete log files.

Request documentation from system admin that identifies the users who are authorized to delete log files.

If unauthorized users are allowed to delete log files, or if documentation that identifies the users who are authorized to delete log files is missing, this is a finding.'
  desc 'fix', 'Configure the OS file permissions on the application server to protect log information from unauthorized deletion.'
  impact 0.5
  ref 'DPMS Target JBoss Enterprise Application Platform 6.3'
  tag check_id: 'C-14738r296211_chk'
  tag severity: 'medium'
  tag gid: 'V-213515'
  tag rid: 'SV-213515r615939_rule'
  tag stig_id: 'JBOS-AS-000175'
  tag gtitle: 'SRG-APP-000120-AS-000080'
  tag fix_id: 'F-14736r296212_fix'
  tag 'documentable'
  tag legacy: ['SV-76745', 'V-62255']
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
