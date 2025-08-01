control 'SV-95893' do
  title 'The Central Log Server must be configured to retain the identity of the original source host or device where the event occurred as part of the log record.'
  desc 'In this case the information producer is the device based on IP address or some other identifier of the device producing the information. The source of the record must be bound to the record using cryptographic means.

Some events servers allow the administrator to retain only portions of the record sent by devices and hosts.

This requirement applies to log aggregation servers with the role of fulfilling the DoD requirement for a central log repository. The syslog, SIEM, or other event servers must retain this information with each log record to support incident investigations.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to include the identity of the original source host or device where the event occurred as part of each aggregated log record.

If the Central Log Server is not configured to include the identity of the original source host or device where the event occurred as part of the aggregated log record, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to include the identity of the original source host or device as part of each aggregated log record.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80845r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81179'
  tag rid: 'SV-95893r1_rule'
  tag stig_id: 'SRG-APP-000516-AU-000330'
  tag gtitle: 'SRG-APP-000516-AU-000330'
  tag fix_id: 'F-87955r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
