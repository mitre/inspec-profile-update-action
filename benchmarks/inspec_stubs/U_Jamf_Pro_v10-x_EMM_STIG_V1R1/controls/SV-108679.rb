control 'SV-108679' do
  title 'The Jamf Pro EMM server must be configured to transfer Jamf Pro EMM server logs to another server for storage, analysis, and reporting.

Note: Jamf Pro EMM server logs include logs of MDM events and logs transferred to the Jamf Pro EMM server by MDM agents of managed devices.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. Since the Jamf Pro EMM server has limited capability to store mobile device log files and perform analysis and reporting of mobile device log files, the Jamf Pro EMM server must have the capability to transfer log files to an audit log management server.

SFR ID: FMT_SMF.1.1(2) i, FAU_STG_EXT.1.1(1)'
  desc 'check', 'Verify the Jamf Pro EMM server is enabled to push syslog:

1. Open Jamf Pro server.
2. Open "Settings".
3. Select "Change Management".
4. Verify the settings for Syslog Server (log file transfer to the syslog server).

If the Jamf Pro EMM server is not configured to enable syslog, this is a finding.'
  desc 'fix', 'Configure the Jamf Pro EMM server to enable syslog:

1. Open Jamf Pro server.
2. Open "Settings".
3. Select "Change Management".
4. Click "Edit".
5. Configure the settings for Syslog Server.
6. Click "Save".'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98425r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99575'
  tag rid: 'SV-108679r1_rule'
  tag stig_id: 'JAMF-10-000520'
  tag gtitle: 'PP-MDM-411054'
  tag fix_id: 'F-105259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
