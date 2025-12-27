control 'SV-69041' do
  title 'The DNS server implementations audit records must be backed up at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on a defined frequency helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', 'Review the DNS system configuration to determine if audit record content is sent to a centralized audit log repository, either directly by the DNS system or by the underlying O/S. 

If the DNS system is not configured to support centralized logging and auditing, this is a finding.'
  desc 'fix', 'Configure the DNS server or the underlying O/S to send audit log content to a centralized logging facility.'
  impact 0.5
  ref 'DPMS Target SRG-APP-DNS'
  tag check_id: 'C-55417r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54795'
  tag rid: 'SV-69041r1_rule'
  tag stig_id: 'SRG-APP-000125-DNS-000012'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-59653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
