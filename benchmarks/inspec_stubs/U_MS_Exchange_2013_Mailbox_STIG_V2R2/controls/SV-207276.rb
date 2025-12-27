control 'SV-207276' do
  title 'Exchange Queue monitoring must be configured with threshold and action.'
  desc 'Monitors are automated "process watchers" that respond to performance changes and can be useful in detecting outages and alerting administrators where attention is needed. Exchange has built-in monitors that enable the administrator to generate alerts if thresholds are reached, better enabling them to react in a timely fashion.  

This field offers choices of alerts when a "warning" or "critical" threshold is reached on the SMTP queue. A good rule of thumb (default) is to issue warnings when SMTP queue growth exceeds 10 minutes and critical messages when it exceeds 20 minutes, which should only exist occasionally. Frequent alerts against this counter may indicate a network or other issue (such as inbound ExchangeMER traffic) that directly impacts email delivery.   

Notification choices include email alert to an email-enabled account (for example, an email Administrator) or invoke a script to take other action (for example, to add an Event to the Microsoft Application Event Log, where external monitors might detect it).'
  desc 'check', 'Note: If a third-party application is performing monitoring functions, the reviewer should verify the application is monitoring correctly and mark the vulnerability NA.

Open the Exchange Management Shell and enter the following command:

perfmon

In the left pane, expand and navigate Performance >> Data Collector Sets >> User Defined. 

If no sets are defined or queues are not being monitored, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

perfmon

In the left pane, navigate to and select Performance >> Data Collector Sets >> User Defined.

Right-click on, navigate to, and configure User Defined >> New >> Data Collector Sets and configure the system to use the data collection set for monitoring the queues.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7534r393341_chk'
  tag severity: 'medium'
  tag gid: 'V-207276'
  tag rid: 'SV-207276r615936_rule'
  tag stig_id: 'EX13-MB-000050'
  tag gtitle: 'SRG-APP-000111'
  tag fix_id: 'F-7534r393342_fix'
  tag 'documentable'
  tag legacy: ['SV-84581', 'V-69959']
  tag cci: ['CCI-000154']
  tag nist: ['AU-6 (4)']
end
