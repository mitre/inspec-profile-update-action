control 'SV-237158' do
  title 'ColdFusion log records must be off-loaded onto a different system or media from the system being logged.'
  desc 'Information system logging capability is critical for accurate forensic analysis.  Off-loading is a common process in information systems with limited log storage capacity.

Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to off-load log records on to a different system or media than the system being logged.

ColdFusion offers the capability to set the number of archived log files to keep before overwriting the file along with the maximum file size before generating an archive.  This allows the administrator to set up a scheduled task or a centralized log management system to pull the log files.'
  desc 'check', 'Locate the log file directory by viewing the "Log directory" setting within the "Logging Settings" page under the "Debugging & Logging" menu.  Have the administrator show the scheduled task or log management application that accesses this directory and stores the log files to another system or media.

If the administrator cannot demonstrate that the log files are being stored to another system or media, this is a finding.'
  desc 'fix', 'Configure a scheduled task or log management application to store the log files to another system or media.'
  impact 0.5
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40377r641567_chk'
  tag severity: 'medium'
  tag gid: 'V-237158'
  tag rid: 'SV-237158r641569_rule'
  tag stig_id: 'CF11-02-000065'
  tag gtitle: 'SRG-APP-000358-AS-000064'
  tag fix_id: 'F-40340r641568_fix'
  tag 'documentable'
  tag legacy: ['SV-76879', 'V-62389']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
