control 'WDNS-22-000115_rule' do
  title 'The Windows 2022 DNS Server audit records must be backed up at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes ensuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto media separate from the system being audited on a defined frequency helps to ensure the audit records will be retained in the event of a catastrophic system failure.

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement applies only to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', "Consult with the system administrator to determine the backup policy in place for Windows 2022 DNS Server.

Review the backup methods used and determine if the backup's methods have been successful at backing up the audit records at least every seven days.

If the organization does not have a backup policy in place for backing up the Windows DNS Server's audit records and/or the backup methods have not been successful at backing up the audit records at least every seven days, this is a finding."
  desc 'fix', "Document and implement a backup policy to back up the DNS server's audit records at least every seven days."
  impact 0.5
  tag check_id: 'C-WDNS-22-000115_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000115'
  tag rid: 'WDNS-22-000115_rule'
  tag stig_id: 'WDNS-22-000115'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-WDNS-22-000115_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
