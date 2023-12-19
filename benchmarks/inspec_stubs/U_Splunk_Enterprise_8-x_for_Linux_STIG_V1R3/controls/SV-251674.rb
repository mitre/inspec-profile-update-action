control 'SV-251674' do
  title 'Splunk Enterprise must be configured to retain the identity of the original source host or device where the event occurred as part of the log record.'
  desc 'In this case the information producer is the device based on IP address or some other identifier of the device producing the information. The source of the record must be bound to the record using cryptographic means.

Some events servers allow the administrator to retain only portions of the record sent by devices and hosts.

This requirement applies to log aggregation servers with the role of fulfilling the DoD requirement for a central log repository. The syslog, SIEM, or other event servers must retain this information with each log record to support incident investigations.'
  desc 'check', 'Review the log records in Splunk Enterprise and verify that the log records retain the identity of the original source host or device where the event occurred.

If the log files do not retain the identity of the original source host or device where the event occurred, this is a finding.'
  desc 'fix', 'Configure Splunk Enterprise to retain the identity of the original source host or device where the event occurred.

Use Splunk Enterprise to modify the props.conf file to include the identity of the original source host or device where the event occurred.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55112r808256_chk'
  tag severity: 'medium'
  tag gid: 'V-251674'
  tag rid: 'SV-251674r808258_rule'
  tag stig_id: 'SPLK-CL-000260'
  tag gtitle: 'SRG-APP-000516-AU-000330'
  tag fix_id: 'F-55066r808257_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
