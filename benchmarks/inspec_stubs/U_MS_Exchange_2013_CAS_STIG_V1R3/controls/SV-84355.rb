control 'SV-84355' do
  title 'Exchange must have Audit record parameters set.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts. This item declares the fields that must be available in the audit log file in order to adequately research events that are logged.

Audit records should include the following fields to supply useful event accounting: 
Object modified, Cmdlet name, Cmdlet parameters, Modified parameters, Caller, Succeeded, and Originating server.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select Name, Identity, AdminAuditLogParameters

If the value of AdminAuditLogParameters is not set to {*}, this is a finding.

Note: The value of {*} indicates all parameters are being audited.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig -AdminAuditLogParameters *'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70177r1_chk'
  tag severity: 'low'
  tag gid: 'V-69733'
  tag rid: 'SV-84355r1_rule'
  tag stig_id: 'EX13-CA-000050'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-75939r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
