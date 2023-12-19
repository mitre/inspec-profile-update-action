control 'SV-233858' do
  title 'The Infoblox system audit records must be backed up at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes ensuring that log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on a defined frequency helps to ensure that, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.'
  desc 'check', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the "Monitoring" tab. 
3. If "Log to External Syslog Servers" is enabled, an External Syslog Server must be configured. 
4. Verify that "Copy Audit Log Message to Syslog" is enabled. 
5. Verify that log messages are received on the remote system.

If no external SYSLOG server is available, verify local procedure to retain audit logs.  

Logs can be downloaded by navigating to Administration >> Logs >> Audit Log tab and pressing the "Download" button. 

When complete, click "Cancel" to exit the "Properties" screen. 

If an external SYSLOG server is not configured or a local policy is not in place to store audit logs, this is a finding.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Grid Properties, or System >> System Manager >> System Properties if using a stand-alone configuration. 
2. Select the "Monitoring" tab. Enable "Log to External Syslog Servers" and configure an "External Syslog Server".
3. Enable the checkbox "Copy Audit Log Message to Syslog".
4. When complete, click "Save & Close" to save the changes and exit the "Properties" screen.
5. Perform a service restart if necessary. 
6. Review Infoblox audit records on the remote SYSLOG server to validate operation.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37043r611094_chk'
  tag severity: 'medium'
  tag gid: 'V-233858'
  tag rid: 'SV-233858r621666_rule'
  tag stig_id: 'IDNS-8X-300002'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-37008r611095_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
