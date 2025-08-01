control 'SV-214406' do
  title 'The log data and records from the IIS 8.5 web server must be backed up onto a different system or media.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up log records to an unrelated system or onto separate media than the system the web server is actually running on helps to assure that, in the event of a catastrophic system failure, the log records will be retained.'
  desc 'check', %q(The IIS 8.5 web server and website log files should be backed up by the system backup.

To determine if log files are backed up by the system backup, determine the location of the web server log files and each website's log files.

Open the IIS 8.5 Manager.

Click the IIS 8.5 server name.

Click the "Logging" icon.

Under "Log File" >> "Directory" obtain the path of the log file.

Once all locations are known, consult with the System Administrator to review the server's backup procedure and policy.

Verify the paths of all log files are part of the system backup.
Verify log files are backed up to an unrelated system or onto separate media than the system the web server is running on.

If the paths of all log files are not part of the system backup and/or not backed up to a separate media, this is a finding.)
  desc 'fix', 'Configure system backups to include the directory paths of all IIS 8.5 web server and website log files.'
  impact 0.5
  ref 'DPMS Target Microsoft IIS 8.5 Server'
  tag check_id: 'C-15616r310266_chk'
  tag severity: 'medium'
  tag gid: 'V-214406'
  tag rid: 'SV-214406r508658_rule'
  tag stig_id: 'IISW-SV-000116'
  tag gtitle: 'SRG-APP-000125-WSR-000071'
  tag fix_id: 'F-15614r310267_fix'
  tag 'documentable'
  tag legacy: ['SV-91393', 'V-76697']
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
