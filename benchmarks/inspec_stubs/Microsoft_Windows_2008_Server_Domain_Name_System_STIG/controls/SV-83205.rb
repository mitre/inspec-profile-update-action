control 'SV-83205' do
  title 'The Windows 2008 DNS Servers audit records must be backed up at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on a defined frequency helps to assure, in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', "Consult with the System Administrator to determine the backup policy in place for Windows DNS Server.

Review the backup methods used and determine if the backup's methods have been successful at backing up the audit records at least every seven days.

If the organization does not have a backup policy in place for backing up the Windows DNS Server's audit records and/or the backup methods have not been successful at backing up the audit records at least every seven days, this is a finding."
  desc 'fix', "Document and implement a backup policy to back up the DNS Server's audit records at least every seven days."
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59445r3_chk'
  tag severity: 'medium'
  tag gid: 'V-58573'
  tag rid: 'SV-83205r1_rule'
  tag stig_id: 'WDNS-AU-000016'
  tag gtitle: 'SRG-APP-000125-DNS-000012'
  tag fix_id: 'F-63957r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
