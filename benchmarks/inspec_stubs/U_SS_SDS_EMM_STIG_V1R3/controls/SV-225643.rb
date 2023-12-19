control 'SV-225643' do
  title 'The Samsung SDS EMM must be configured to transfer Samsung SDS EMM logs to another server for storage, analysis, and reporting.

Note: Samsung SDS EMM logs include logs of MDM events and logs transferred to the Samsung SDS EMM by MDM agents of managed devices.'
  desc 'Audit logs enable monitoring of security-relevant events and subsequent forensics when breaches occur. Since the Samsung SDS EMM has limited capability to store mobile device log files and perform analysis and reporting of mobile device log files, the Samsung SDS EMM must have the capability to transfer log files to an audit log management server.

SFR ID: FMT_SMF.1.1(2) c.8, FAU_STG_EXT.1.1(1)'
  desc 'check', 'Review the Samsung SDS EMM configuration settings and verify the server is configured to transfer Samsung SDS EMM logs to another server for storage, analysis, and reporting. 

On the MDM console, do the following:
1. Go to Setting >> Server >> Configuration.
2. Click "Audit" at the top of the window and verify audit log server and other information is listed.

If the MDM console is not configured to transfer audit logs to an audit log server, this is a finding.

Note: Samsung SDS EMM logs include logs of MDM events and logs transferred to the Samsung SDS EMM by MDM agents of managed devices.'
  desc 'fix', 'Configure the Samsung SDS EMM to transfer Samsung SDS EMM logs to another server for storage, analysis, and reporting.

On the MDM console, do the following:
1. Go to Setting >> Server >> Configuration.
2. Click "Audit" at the top of the window and enter the audit log server and other information.'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27344r560953_chk'
  tag severity: 'medium'
  tag gid: 'V-225643'
  tag rid: 'SV-225643r588007_rule'
  tag stig_id: 'SSDS-00-000510'
  tag gtitle: 'PP-MDM-411054'
  tag fix_id: 'F-27332r560954_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
