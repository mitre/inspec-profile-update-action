control 'SV-223248' do
  title 'SharePoint must reject or delay, as defined by the organization, network traffic generated above configurable traffic volume thresholds.'
  desc 'It is critical when a system is at risk of failing to process audit logs as required; actions are automatically taken to mitigate the failure or risk of failure.

One method used to thwart the auditing system is for an attacker to attempt to overwhelm the auditing system with large amounts of irrelevant data. The end result is audit logs that are either overwritten and activity thereby erased or disk space that is exhausted and any future activity is no longer logged.

In many system configurations, the disk space allocated to the auditing system is separate from the disks allocated for the operating system; therefore, this may not result in a system outage.'
  desc 'check', 'Review the SharePoint server configuration to ensure network traffic generated above configurable traffic volume thresholds, as defined by the organization or site SSP, is rejected or delayed.

Log on to the server.

Click Start.

Type Internet Information Services Manager in the Search Bar, click Enter.

Determine which IIS Sites are subject to user traffic. This is generally the IIS site hosting the Content Web Application.

For each site IIS site subject to user traffic, select the site.

Click Advanced Settings.

Expand Connection Limits.

Ensure the following settings possess a value:
-Connection Time-Out
-Maximum Bandwidth
-Maximum Concurrent Connections

Repeat steps for each site subject to user traffic.

Otherwise, this is a finding.'
  desc 'fix', 'Configure SharePoint to reject or delay, as defined by the organization or site SSP, network traffic generated above configurable traffic volume thresholds.

Log on to the server.

Click Start.

Type Internet Information Services Manager in the Search Bar, click Enter.

Determine which IIS Sites are subject to user traffic. This is generally the IIS site hosting the Content Web Application.

For each site IIS site subject to user traffic, select the site.

Click Advanced Settings.

Expand Connection Limits.

Ensure the following settings possess a value:
-Connection Time-Out
-Maximum Bandwidth
-Maximum Concurrent Connections

Repeat steps for each site subject to user traffic.'
  impact 0.5
  ref 'DPMS Target Microsoft SharePoint 2013'
  tag check_id: 'C-24921r430804_chk'
  tag severity: 'medium'
  tag gid: 'V-223248'
  tag rid: 'SV-223248r612235_rule'
  tag stig_id: 'SP13-00-000060'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-24909r430805_fix'
  tag 'documentable'
  tag legacy: ['SV-74385', 'V-59955']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
