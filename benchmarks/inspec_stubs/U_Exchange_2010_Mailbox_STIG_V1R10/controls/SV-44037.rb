control 'SV-44037' do
  title 'Audit record parameters must be set.'
  desc 'Log files help establish a history of activities, and can be useful in detecting attack attempts.   This item declares the fields that must be available in the audit log file in order to adequately research events that are logged. 
Audit records should include the following fields to supply useful event accounting: 
Object modified, Cmdlet name, Cmdlet parameters, Modified parameters, Caller, Succeeded, and Originating server.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select AdminAuditLogParameters

If the value of 'AdminAuditLogParameters' is not set to '{*}', this is a finding.

Note: The value of {*} indicates all parameters are being audited."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig -AdminAuditLogParameters *'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41724r1_chk'
  tag severity: 'low'
  tag gid: 'V-33617'
  tag rid: 'SV-44037r2_rule'
  tag stig_id: 'Exch-2-833'
  tag gtitle: 'Exch-2-833'
  tag fix_id: 'F-37509r1_fix'
  tag 'documentable'
end
