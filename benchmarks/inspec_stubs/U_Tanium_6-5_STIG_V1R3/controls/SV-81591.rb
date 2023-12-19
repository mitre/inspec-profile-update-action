control 'SV-81591' do
  title 'A connector must be configured to send log data to offline log collection.'
  desc 'While the Tanium Server records audit log entries to the Tanium SQL database, retrieval and aggregation of log data through the Tanium console is not efficient.  

The Tanium Connect module allows for ArcSight, McAfee SIEM, SIEM, Splunk SIEM, and LogRhythm connectors in order to facilitate forensic data retrieval and aggregation efficiently.'
  desc 'check', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Connect" tab.

Click on "Configured Connectors".

Review for any configured "ArcSight", “McAfee SIEM", "SIEM", "Splunk" or "LogRhythm" connectors.

If SIEM connectors are not configured for send log data to offline log collection, this is a finding.'
  desc 'fix', 'Using a web browser on a system that has connectivity to the Tanium Server, access the Tanium Server web user interface (UI) and log on with CAC.

Click on "Administration".

Select the "Connect" tab.

Click on "Connector Templates".

Choose and configure a template for a SIEM located at the site.'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67737r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67101'
  tag rid: 'SV-81591r1_rule'
  tag stig_id: 'TANS-SV-000029'
  tag gtitle: 'SRG-APP-000358'
  tag fix_id: 'F-73201r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
