control 'SV-90919' do
  title 'If any logs are stored locally which are not sent to the centralized audit server, CounterACT must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Regularly backing up audit records to a different system or onto separate media than the system being audited helps to ensure, in the event of a catastrophic system failure, the audit records will be retained.

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement can be met by using of a syslog/audit log server if the device is configured to send logs to that server.

Backup requirements would be levied on the target server but are not a part of this check.'
  desc 'check', 'If all audit logs for the Enterprise Manager and appliances are sent to an audit log, this is not a finding.

Determine if CounterACT backs up local logs on the Enterprise Manager or appliances at least every seven days onto a different system or system component than the system or component being audited. This requirement may be verified by configuration review.

1. Open the CounterACT Console and select Tools >> Options.
2. Select the "+" next to "Advanced" menu (toward the bottom).
3. Select the “Backup” submenu.
4. On the "System Backup" tab, verify the "Enable System Backup" radio button is selected.
5. Verify the Backup schedule is selected to at least "weekly".
6. On the "Backup Server" tab, verify an external backup server is configured with SFTP or SCP (and appropriate port/protocol requirements).

If the network device does not back up audit records at least every seven days onto a different system or system component than the system or component being audited, this is a finding.'
  desc 'fix', 'Configure CounterACT to back up locally stored audit records on the Enterprise Manager or the appliances at least every seven days onto a different system or system component than the system or component being audited.

1. Open the CounterACT Console and select Tools >> Options.
2. Select the "+" next to "Advanced" menu (toward the bottom).
3. Select the “Backup” submenu.
4. On the "System Backup" tab, ensure the "Enable System Backup" radio button is selected.
5. Ensure the Backup schedule is selected to at least "weekly".
6. On the "Backup Server" tab, verify an external backup server is configured with SFTP or SCP (and appropriate port/protocol requirements).'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76231'
  tag rid: 'SV-90919r1_rule'
  tag stig_id: 'CACT-NM-000023'
  tag gtitle: 'SRG-APP-000125-NDM-000241'
  tag fix_id: 'F-82867r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
