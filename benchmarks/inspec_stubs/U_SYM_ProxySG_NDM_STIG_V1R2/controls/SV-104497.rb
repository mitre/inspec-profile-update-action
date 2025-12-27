control 'SV-104497' do
  title 'Symantec ProxySG must be configured to support centralized management and configuration of the audit log.'
  desc 'Without the ability to centrally manage the content captured in the audit records, identification, troubleshooting, and correlation of suspicious behavior would be difficult and could lead to a delayed or incomplete analysis of an ongoing attack.

The DoD requires centralized management of all network component audit record content. Network components requiring centralized audit log management must have the capability to support centralized management. The content captured in audit records must be managed from a central location (necessitating automation). Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Ensure at least one Syslog server and local files are configured to support requirements. However, the Syslog itself must also be configured to filter event records so it is not overwhelmed.'
  desc 'check', 'Verify event logging to a syslog server is enabled.

1. Log on to the Web Management Console.
2. Click Maintenance >> Event Logging >> Syslog.
3. Ensure that the "Enable Syslog" checkbox is checked and that one or more "syslog loghosts" are specified.

If Symantec ProxySG does not off-load audit records onto a different system or media than the system being audited, this is a finding.'
  desc 'fix', 'Configure event logging to a remote events server to ensure that event logs are recorded on a different system.

To configure Syslog:
1. Log on to the Web Management Console.
2. Click Maintenance >> Event Logging >> Syslog.
3. Enter the IP address or name of a syslog server, click "OK".
4. Repeat step 3 for any additional syslog servers.
5. Click "Apply".'
  impact 0.5
  ref 'DPMS Target Symantec ProxySG NDM'
  tag check_id: 'C-93857r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94667'
  tag rid: 'SV-104497r1_rule'
  tag stig_id: 'SYMP-NM-000080'
  tag gtitle: 'SRG-APP-000515-NDM-000325'
  tag fix_id: 'F-100785r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
