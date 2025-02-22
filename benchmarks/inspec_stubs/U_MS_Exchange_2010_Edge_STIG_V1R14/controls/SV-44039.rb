control 'SV-44039' do
  title 'Queue monitoring must be configured with threshold and action.'
  desc 'Monitors are automated “process watchers” that respond to performance changes, and can be useful in detecting outages and alerting administrators where attention is needed. Exchange has built-in monitors that enable the administrator to generate alerts if thresholds are reached, better enabling them to react in a timely fashion. 

The intent of this check is for system administrators to have awareness of performance changes on their network. 

Notification choices include email an alert to an email-enabled account, for example, an email Administrator, or invoke a script to take other action, for example, to add an Event to the Microsoft Application Event Log, where external monitors might detect it.

Data elements configured to be monitored should be specific to the organization’s network.
.'
  desc 'check', 'Note: If a third-party application is performing monitoring functions, the reviewer should verify the application is monitoring correctly and mark the vulnerability NA.

Open the Exchange Management Shell and enter the following command:
perfmon

In the left pane, expand and navigate Data Collector Sets >> User Defined. 
If no sets are defined or queues are not being monitored, this is a finding.'
  desc 'fix', 'Open the Exchange Management Console

In the left pane, navigate to and select Microsoft Exchange On-Premises <server.domain> --> Toolbox 

In the Right pane double click on Performance Monitor 

In the left pane, navigate to and select Performance Logs and Alerts --> Data Collector Sets --> User Defined 

Right click on User Defined and configure the system to use User Defined data collection for monitoring the queues.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41726r9_chk'
  tag severity: 'medium'
  tag gid: 'V-33619'
  tag rid: 'SV-44039r3_rule'
  tag stig_id: 'Exch-2-842'
  tag gtitle: 'Exch-2-842'
  tag fix_id: 'F-37511r5_fix'
  tag 'documentable'
end
