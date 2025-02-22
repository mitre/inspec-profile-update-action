control 'SV-204789' do
  title 'The application server must off-load log records onto a different system or media from the system being logged.'
  desc 'Information system logging capability is critical for accurate forensic analysis. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

Off-loading is a common process in information systems with limited log storage capacity.

Centralized management of log records provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to off-load log records onto a different system or media than the system being logged.'
  desc 'check', 'Verify the log records are being off-loaded to a separate system or transferred from the application server to a storage location other than the application server itself.

The system administrator of the device may demonstrate this capability using a log management application, system configuration, or other means.

If logs are not being off-loaded, this is a finding.'
  desc 'fix', 'Configure the application server to off-load the logs to a remote log or management server.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4909r283014_chk'
  tag severity: 'medium'
  tag gid: 'V-204789'
  tag rid: 'SV-204789r508029_rule'
  tag stig_id: 'SRG-APP-000358-AS-000064'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-4909r283015_fix'
  tag 'documentable'
  tag legacy: ['V-57423', 'SV-71695']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
