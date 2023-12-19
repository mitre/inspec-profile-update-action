control 'SV-251668' do
  title 'Splunk Enterprise must be configured to offload log records onto a different system or media than the system being audited.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity. Although this may be part of the operating system function, for the enterprise events management system, this is most often a function managed through the application since it is a critical function and requires the use of a large amount of external storage.'
  desc 'check', 'Verify the Splunk Enterprise Environment is configured to offload log records to an external source.

On the forwarder, check that the outputs.conf file is configured with the details of the source that the logs will be sent to (e.g. Hostname, port# etc.).

If the Splunk Enterprise is not configured to offload log records to an external source, this is a finding.'
  desc 'fix', 'This configuration is performed on the machine used as a forwarder, which is always a separate machine regardless of environment.

On the forwarders, configure the outputs.conf with the information of the indexer that the data will be sent to for analysis. 

This configuration is performed on the machine used as the assigned indexer to the forwarder in a distributed environment.

On the indexer, configure the inputs.conf file with the information of the forwarders that are sending the data for analysis.'
  impact 0.5
  ref 'DPMS Target Splunk Enterprise 8.x for Linux'
  tag check_id: 'C-55106r808238_chk'
  tag severity: 'medium'
  tag gid: 'V-251668'
  tag rid: 'SV-251668r808240_rule'
  tag stig_id: 'SPLK-CL-000150'
  tag gtitle: 'SRG-APP-000358-AU-000100'
  tag fix_id: 'F-55060r808239_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
