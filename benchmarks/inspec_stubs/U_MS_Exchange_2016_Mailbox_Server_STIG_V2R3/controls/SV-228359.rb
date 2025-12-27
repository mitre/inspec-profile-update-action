control 'SV-228359' do
  title 'Exchange Audit record parameters must be set.'
  desc 'Log files help establish a history of activities and can be useful in detecting attack attempts. This item declares the fields that must be available in the audit log file in order to adequately research events that are logged. 

Audit records should include the following fields to supply useful event accounting: 
Object modified, Cmdlet name, Cmdlet parameters, Modified parameters, Caller, Succeeded, and Originating server.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-AdminAuditLogConfig | Select AdminAuditLogParameters

Note: The value of "*" indicates all parameters are being audited.

If the value of "AdminAuditLogParameters" is not set to "*", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-AdminAuditLogConfig -AdminAuditLogParameters *'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30592r496873_chk'
  tag severity: 'low'
  tag gid: 'V-228359'
  tag rid: 'SV-228359r612748_rule'
  tag stig_id: 'EX16-MB-000060'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-30577r496874_fix'
  tag 'documentable'
  tag legacy: ['SV-95343', 'V-80633']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
