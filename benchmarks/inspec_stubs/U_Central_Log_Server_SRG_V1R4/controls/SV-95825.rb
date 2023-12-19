control 'SV-95825' do
  title 'Where multiple log servers are installed in the enclave, each log server must be configured to aggregate log records to a central aggregation server or other consolidated events repository.'
  desc 'Log servers (e.g., syslog servers) are often used on network segments to consolidate from the devices and hosts on that network segment. However, this does not achieve compliance with the DoD requirement for a centralized enclave log server.

To comply with this requirement, create a central log server that aggregates multiple log servers or use another method to ensure log analysis and management is centrally managed and available to enterprise forensics and analysis tools. This server is often called a log aggregator, SIEM, or events server.'
  desc 'check', 'Examine the network architecture and documentation.

If the log server being reviewed is one of multiple log servers in the enclave or on a network segment, verify that an aggregation server exists and that the log server under review is configured to send records received from the host and devices to the aggregation server or centralized SIEM/events sever.

Where multiple log servers are installed in the enclave, if each log server is not configured to send log records to a central aggregation server or other consolidated events repository, this is a finding.'
  desc 'fix', 'Where multiple log servers are installed in the enclave, configure each log server to forward logs to a consolidated aggregation server.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81111'
  tag rid: 'SV-95825r1_rule'
  tag stig_id: 'SRG-APP-000086-AU-000390'
  tag gtitle: 'SRG-APP-000086-AU-000390'
  tag fix_id: 'F-87883r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
