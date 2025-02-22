control 'SV-95823' do
  title 'Time stamps recorded on the log records in the Central Log Server must be configured to synchronize to within one second of the host server or, if NTP is configured directly in the log server, the NTP time source must be the same as the host and devices within its scope of coverage.'
  desc 'If the application is not configured to collate records based on the time when the events occurred, the ability to perform forensic analysis and investigations across multiple components is significantly degraded. If the SIEM or other Central Log Server is out of sync with the host and devices for which it stores event logs, this may impact the accuracy of the records stored.

Log records are time correlated if the time stamps in the individual log records can be reliably related to the time stamps in other log records to achieve a time ordering of the records within an organization-defined level of tolerance.

This requirement applies only to applications that compile system-wide log records for multiple systems or system components.

Note: The actual configuration and security requirements for NTP is handled in the host OS or NDM STIGs that are also required as part of a Central Log Server review.'
  desc 'check', 'Examine the time stamp that indicates when the Central Log Server received the log records.

Verify the time is synchronized to within one second of the host server.

If an NTP client is configured within the Central Log Server application, verify it is configured to use the same NTP time source as the host and devices within its scope of coverage.

If time stamps recorded on the log records in the Central Log Server are not configured to synchronize to within one second of the host server or the log server application is not configured to use the same NTP time source as the host and devices within its scope of coverage, this is a finding.'
  desc 'fix', 'Configure the Central Log Server such that time stamps on the log records are synchronized to within one second of the host server.

If applicable, configure the Central Log Server NTP client to use the same NTP time source as the host and devices within its scope of coverage.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80763r1_chk'
  tag severity: 'low'
  tag gid: 'V-81109'
  tag rid: 'SV-95823r1_rule'
  tag stig_id: 'SRG-APP-000086-AU-000030'
  tag gtitle: 'SRG-APP-000086-AU-000030'
  tag fix_id: 'F-87881r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
