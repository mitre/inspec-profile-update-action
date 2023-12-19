control 'SV-82535' do
  title 'The A10 Networks ADC must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained. This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

There are two ways to meet this requirement; either by configuring the device to send the audit and event log to the syslog servers or by scheduling periodic exports of the audit and event logs.'
  desc 'check', 'This requirement can be met by use of a syslog/audit log server if the device is configured to send logs to that server.

Review the device configuration.

Enter the command to view the logging policy:
sho log policy

If the output shows syslog hosts are configured, this not is a finding.

If the output shows syslog as enabled, this is not a finding.

If it is not configured to send audit and event logs to a syslog server, enter the command to view the scheduled backup of the log:
show backup

If the there is no backup configured, this is a finding.

If the backup period is not seven days or less, this is a finding.

If the last backup failed and it has been more than seven days since the last backup, this is a finding.'
  desc 'fix', 'To configure the network device to send audit and event logs to a syslog server:

The following command enables logging using the syslog protocol:
logging syslog [severity-level]
The severity level can be any one of the following options: emergency, alert, critical, error, warning, notification, information, debugging.

The following command specifies where to send syslog messages:
logging host [ipaddr][port protocol-port]
"ipaddr" is the IP address of the syslog server. Up to 10 remote logging servers are supported.
"port" is the protocol port number to which to send messages. All logging servers must use the same port. The default port is 514.

The following command sends the audit log records to a specific syslog server (Note: The event log and the audit log are separate logs):
logging auditlog host [ipaddr | hostname] [facility facility-name]
"ipaddr" is the IP address of the syslog server.
"hostname" is the hostname of the syslog server.
"facility" is the facility code to use for messages sent from the device.

To configure the network device to backup logs to a file server:

The following command periodically backs up (copies) the log to a specific server:
backup periodically log [hour num | day num | week num] [use-mgmt-port] url
The hour, day, and week options are the frequency of backups.
The use-mgmt-port option uses the management interface as the source interface for the connection to the remote device.
The url specifies the file transfer protocol, username (if required), and directory path. Since secure protocols are required, use either SCP or SFTP:
scp://[user@]host/file/ or sftp://[user@]host/file/
"user" is the account configured on the backup server.
"host" is the backup server.
"file" is the name of the file on the backup server.

When the command is entered, the device will prompt for the password of the backup server. This password is saved to a profile.'
  impact 0.3
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68605r1_chk'
  tag severity: 'low'
  tag gid: 'V-68045'
  tag rid: 'SV-82535r1_rule'
  tag stig_id: 'AADC-NM-000042'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-74161r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
