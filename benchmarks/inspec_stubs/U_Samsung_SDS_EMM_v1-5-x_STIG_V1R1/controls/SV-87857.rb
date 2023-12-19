control 'SV-87857' do
  title 'The Samsung SDS EMM server must be configured to transfer MD audit logs and Samsung SDS EMM server logs to another server for analysis and reporting.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. Since the Samsung SDS EMM server has limited capability to store MD log files and perform analysis and reporting of MD log files, the Samsung SDS EMM server must have the capability to transfer log files to an audit log management server.

SFR ID: FMT_SMF.1.1(2) Refinement, f'
  desc 'check', 'The following describes how the MDM server transfers MD audit logs and MDM server logs to another server for analysis and reporting.

Ask the system administrator to identify which audit management server Samsung SDS EMM server logs are transferred to. Verify that the audit management server contains records of the MD audit logs and MDM server logs, which have been transferred from the Samsung SDS EMM server. If logs are not automatically transferred periodically, verify logs are transferred manually at least daily.

If the Samsung SDS EMM server is not configured to transfer MD audit logs to another server (automatically or manually), this is a finding.'
  desc 'fix', 'The following describes how the MDM server can transfer MD audit logs and MDM server logs to another server for analysis and reporting. This is a manual process that has to be performed by the administrator periodically.

To transfer Samsung SDS EMM server logs, on the MDM console, do the following:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Service Overview >> Logs >> Audit Logs.
3) Choose a date and click the "Export" button to export the selected Audit data to a file on the administrator’s workstation.
4) Follow the browser-specific instructions to save the comma-separated values file.

To transfer MD audit logs, on the MDM console, do the following:
1) Log in to the Samsung SDS EMM Server Admin Console using a web browser.
2) Go to Service Overview >> Logs >> Device Logs.
3) Choose the desired device in the left side of the “Device Logs” screen.
4) Choose the Export action in the row for the device log to be saved to export the selected MD audit log to a file on the administrator’s workstation.
5) Follow the browser-specific instructions to save the comma-separated values file.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM 1.5.x'
  tag check_id: 'C-73307r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73205'
  tag rid: 'SV-87857r1_rule'
  tag stig_id: 'SEMM-15-000320'
  tag gtitle: 'PP-MDM-201129'
  tag fix_id: 'F-79651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000128', 'CCI-000129', 'CCI-000169', 'CCI-000366', 'CCI-001571']
  tag nist: ['AU-2 (4)', 'AU-2 a', 'AU-12 a', 'CM-6 b', 'AU-2 a']
end
