control 'SV-207272' do
  title 'Exchange Audit record parameters must be set.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts. This item declares the fields that must be available in the audit log file in order to adequately research events that are logged. 

Audit records should include the following fields to supply useful event accounting: 
Object modified, Cmdlet name, Cmdlet parameters, Modified parameters, Caller, Succeeded, and Originating server.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select AdminAuditLogParameters

Note: The value of {*} indicates all parameters are being audited.

If the value of AdminAuditLogParameters is not set to {*}, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig -AdminAuditLogParameters *'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7530r393329_chk'
  tag severity: 'low'
  tag gid: 'V-207272'
  tag rid: 'SV-207272r615936_rule'
  tag stig_id: 'EX13-MB-000030'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-7530r393330_fix'
  tag 'documentable'
  tag legacy: ['SV-84573', 'V-69951']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
