control 'SV-251664' do
  title 'In a distributed environment, Splunk Enterprise indexers must be configured to ingest log records from its forwarders.'
  desc 'Log servers (e.g., syslog servers) are often used on network segments to consolidate from the devices and hosts on that network segment. However, this does not achieve compliance with the DoD requirement for a centralized enclave log server.

To comply with this requirement, create a central log server that aggregates multiple log servers, or use another method to ensure log analysis and management is centrally managed and available to enterprise forensics and analysis tools. This server is often called a log aggregator, SIEM, or events server.'
  desc 'check', 'This check is applicable to the instance with the Indexer role or the Forwarder role, which may be a different instance in a distributed environment.

Verify the Splunk Enterprise Environment is configured to ingest log records from different hosts.

On the forwarders, check if the output.conf file is configured with the details of the indexer is ingesting the log data (e.g., Hostname, port# etc.).

On the indexer, check if the input.conf file is configured with the details of the forwarders that are sending the data.

If the Splunk Enterprise is not configured to perform analysis of log records from across multiple hosts, this is a finding.'
  desc 'fix', 'On the forwarders, configure the outputs.conf with the information of the indexer that the data will be sent to for analysis.

On the indexer, configure the inputs.conf file with the information of the forwarders that are sending the data for analysis.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55102r808226_chk'
  tag severity: 'medium'
  tag gid: 'V-251664'
  tag rid: 'SV-251664r808228_rule'
  tag stig_id: 'SPLK-CL-000110'
  tag gtitle: 'SRG-APP-000086-AU-000390'
  tag fix_id: 'F-55056r808227_fix'
  tag 'documentable'
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
