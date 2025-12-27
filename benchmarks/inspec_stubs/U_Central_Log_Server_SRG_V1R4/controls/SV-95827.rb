control 'SV-95827' do
  title 'The Central Log Server log records must be configured to use the syslog protocol or another industry standard format (e.g., Windows event protocol) that can be used by typical analysis tools.'
  desc 'Without a standardized format for log records, the ability to perform forensic analysis may be more difficult. Standardization facilitates production of event information that can be more readily analyzed and correlated.

Log information that is normalized to common standards promotes interoperability and exchange of such information between dissimilar devices and information systems. 

If logging mechanisms within applications that send records to the centralized audit system do not conform to standardized formats, the audit system may convert the records into a standardized format when compiling system-wide audit trails. Thus, although the application and other system components should send the information in a standardized format, ultimately the audit aggregation server is responsible for ensuring the records are compiled to meet this requirement.'
  desc 'check', 'Examine the configuration.

Verify log records are configured to use the syslog protocol or another industry standard format (e.g., Windows event protocol) that can be used by a typical analysis tools.

If the Central Log Server log records are not configured to use the syslog protocol or another industry standard format (e.g., Windows event protocol) that can be used by typical analysis tools, this is a finding.'
  desc 'fix', 'Configure the Central Log Server log records to use the syslog protocol or another industry standard format (e.g., Windows event protocol) that can be used by typical analysis tools.'
  impact 0.3
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80767r1_chk'
  tag severity: 'low'
  tag gid: 'V-81113'
  tag rid: 'SV-95827r1_rule'
  tag stig_id: 'SRG-APP-000088-AU-000040'
  tag gtitle: 'SRG-APP-000088-AU-000040'
  tag fix_id: 'F-87885r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001353']
  tag nist: ['AU-12 (2)']
end
