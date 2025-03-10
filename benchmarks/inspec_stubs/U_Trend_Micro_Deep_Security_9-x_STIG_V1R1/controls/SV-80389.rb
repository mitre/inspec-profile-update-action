control 'SV-80389' do
  title 'Trend Deep Security must back up audit records at least every seven days onto a different system or system component than the system or component being audited.'
  desc 'Protection of log data includes assuring log data is not accidentally lost or deleted. Backing up audit records to a different system or onto separate media than the system being audited on an organizationally defined frequency helps to assure in the event of a catastrophic system failure, the audit records will be retained. 

This helps to ensure a compromise of the information system being audited does not also result in a compromise of the audit records.

This requirement only applies to applications that have a native backup capability for audit records. Operating system backup requirements cover applications that do not provide native backup functions.'
  desc 'check', 'Review the Trend Deep Security server configuration to ensure audit records are backed up at least every seven days onto a different system or system component than the system or component being audited.

Verify the application backup frequency by reviewing the configuration settings in Administration >> System Settings >> SIEM

If the "Forward System Events to a remote computer (via Syslog)" is not enabled with the proper configuration settings, this is a finding.'
  desc 'fix', 'Configure the Trend Deep Security server to back up audit records at least every seven days onto a different system or system component than the system or component being audited.

Configure the application to forward audit records to a log management tool for backup and storage.
Go to Administration >> System Settings >> SIEM
Enable "Forward System Events to a remote computer (via Syslog)"

Configure the following:

   Hostname or IP address to which events should be sent
   UDP port to which events should be sent
   Syslog Facility
   Syslog Format'
  impact 0.5
  ref 'DPMS Target Trend Micro Deep Security 9.x'
  tag check_id: 'C-66547r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65899'
  tag rid: 'SV-80389r1_rule'
  tag stig_id: 'TMDS-00-000120'
  tag gtitle: 'SRG-APP-000125'
  tag fix_id: 'F-71975r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001348']
  tag nist: ['AU-9 (2)']
end
