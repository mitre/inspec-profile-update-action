control 'SV-104509' do
  title 'Symantec ProxySG must back up event logs onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.'
  desc 'check', 'Verify event logging to a remote events collection server is configured in order to send event logs to a different system.

1. Log on to the Web Management Console.
2. Click Maintenance >> Event Logging >> Syslog.
3. Confirm that "Syslog" is "Enabled" and a syslog server is specified.

If Symantec ProxySG does not back up event logs onto a different system or system component than the system or component being audited, this is a finding.'
  desc 'fix', 'Configure event logging to a remote events server to ensure that event logs are recorded on a different system.

To configure Syslog:
1. Log on to the Web Management Console.
2. Click Maintenance >> Event Logging >> Syslog.
3. Enter the IP address or name of a syslog server, click "OK".
4. Repeat step 3 for any additional syslog servers.
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93869r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94679'
  tag rid: 'SV-104509r1_rule'
  tag stig_id: 'SYMP-NM-000140'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-100797r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
