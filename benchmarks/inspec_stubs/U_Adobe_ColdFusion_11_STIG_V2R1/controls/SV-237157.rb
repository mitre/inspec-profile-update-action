control 'SV-237157' do
  title 'ColdFusion must allocate log record storage capacity in accordance with organization-defined log record storage requirements.'
  desc 'The proper management of log records not only dictates proper archiving processes and procedures be established, it also requires allocating enough storage space to maintain the logs online for a defined period of time.

If adequate online log storage capacity is not maintained, intrusion monitoring, security investigations, and forensic analysis can be negatively affected.

It is important to keep a defined amount of logs online and readily available for investigative purposes. The logs may be stored on the application server until they can be archived to a log system or, in some instances, a Storage Area Network (SAN).  Regardless of the method used, log record storage capacity must be sufficient to store log data when the data cannot be off-loaded to a log system or a SAN.

ColdFusion handles logs by allowing the administrator to specify a log file size and how many archives to keep online.  This allows the administrator to correctly size the storage needed to meet the requirements of the organization for how log audit files should be available online and configure the storage needed to meet the requirement before off-loading archives to off-line storage.'
  desc 'check', 'Locate the log file directory by viewing the "Log directory" setting within the "Logging Settings" page under the "Debugging & Logging" menu.  Also make note of the "Maximum number of archives" and "Maximum file size (in kilobytes)" settings.  Next, view the number of log files generated.  This can be found by accessing the "Log Files" page under the "Debugging & Logging" menu.  Count the number of log files.

If "Maximum number of archives" multiplied by "Maximum file size (in kilobytes)" multiplied by the number of log files is larger than the storage where the log directory is located, this is a finding.'
  desc 'fix', 'Move the location of the log files to a directory that has sufficient storage to meet the organization-defined log record storage requirement.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40376r641564_chk'
  tag severity: 'medium'
  tag gid: 'V-237157'
  tag rid: 'SV-237157r641566_rule'
  tag stig_id: 'CF11-02-000064'
  tag gtitle: 'SRG-APP-000357-AS-000038'
  tag fix_id: 'F-40339r641565_fix'
  tag 'documentable'
  tag legacy: ['SV-76877', 'V-62387']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
