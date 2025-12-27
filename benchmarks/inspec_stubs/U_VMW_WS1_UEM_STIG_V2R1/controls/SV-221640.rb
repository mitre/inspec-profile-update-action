control 'SV-221640' do
  title 'The Workspace ONE UEM server must be configured to transfer Workspace ONE UEM server logs to another server for storage, analysis, and reporting.

Note: Workspace ONE UEM server logs include logs of MDM events and logs transferred to the Workspace ONE UEM server by MDM agents of managed devices.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. Since the Workspace ONE UEM server has limited capability to store mobile device log files and perform analysis and reporting of mobile device log files, the Workspace ONE UEM server must have the capability to transfer log files to an audit log management server.

SFR ID: FMT_SMF.1.1(2) c.8, FAU_STG_EXT.1.1(1)'
  desc 'check', 'Review the Workspace ONE UEM server configuration settings and verify the server is configured to transfer Workspace ONE UEM server logs to another server for storage, analysis, and reporting.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> System >> Enterprise Integration >> Syslog.
3. If "Syslog Integration" is set to "DISABLED", this is a finding.
4. Examine the syslog configuration (server hostname, protocol, port, syslog facility, message tag, message content) for conformance with operational standards. If any are not set according to the standards, this is a finding.

Note: Workspace ONE UEM server logs include logs of MDM events and logs transferred to the Workspace ONE UEM server by MDM agents of managed devices.'
  desc 'fix', 'Configure the Workspace ONE UEM server to transfer Workspace ONE UEM server logs to another server for storage, analysis, and reporting.

On the MDM console, do the following:
1. Authenticate to the Workspace ONE UEM console as the administrator.
2. Navigate to Groups & Settings >> All Settings >> System >> Enterprise Integration >> Syslog.
3. Set "Syslog Integration" to "ENABLED".
4. Configure syslog server hostname, protocol, port, syslog facility, message tag, message content according to organizational standards.
5. Click "SAVE".
6. Verify changes save successfully and Workspace ONE UEM server can transfer audit logs to the new syslog server.'
  impact 0.5
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-23355r416758_chk'
  tag severity: 'medium'
  tag gid: 'V-221640'
  tag rid: 'SV-221640r588007_rule'
  tag stig_id: 'VMW1-00-000500'
  tag gtitle: 'PP-MDM-411054'
  tag fix_id: 'F-23344r416759_fix'
  tag 'documentable'
  tag legacy: ['SV-111279', 'V-102323']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
