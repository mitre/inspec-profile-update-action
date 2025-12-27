control 'SV-215651' do
  title 'The Windows 2012 DNS Server logging must be enabled to record events from all DNS server functions.'
  desc 'DNS server performance can be affected when additional logging is enabled; however, the enhanced DNS logging and diagnostics feature in Windows Server 2012 R2 is designed to have a very low impact on performance. Enhanced DNS logging and diagnostics in Windows Server 2012 R2 and later includes DNS Audit events and DNS Analytic events. DNS audit logs are enabled by default and do not significantly affect DNS server performance. DNS analytical logs are not enabled by default and typically will only affect DNS server performance at very high DNS query rates.

Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server.

In order to compile an accurate risk assessment, it is essential for security personnel to know what is being performed on the system, where an event occurred, when an event occurred, and by whom the event was triggered. Logging the actions of specific events provides a means to investigate an attack, recognize resource utilization or capacity thresholds, or identify an improperly configured DNS system. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis. It is important, therefore, to log all possible data related to events so they can be correlated and analyzed to determine the risk.

Data required to be captured include: whether an event was successful or failed, the event type or category, timestamps for when the event occurred, where the event originated, who/what initiated the event, the effect the event had on the DNS implementation, and any processes associated with the event.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Open an elevated Windows PowerShell prompt on a DNS server using the Domain Admin or Enterprise Admin account.

Use the "Get-DnsServerDiagnostics" cmdlet to view the status of individual diagnostic events.

Verify the following diagnostic events are set to "True":
Queries, Answers, Notifications, Update, QuestionTransactions, UnmatchedResponse,UseSystemEventLog 

Also set to “True” should be: 
EnableLoggingForLocalLookupEvent
EnableLoggingForPluginDLLEvent 
EnableLoggingForRecursiveLookupEvent
EnableLoggingForRemoteServerEvent
EnableLoggingForRemoteServerEvent
EnableLoggingForServerStartStopEvent
EnableLoggingForTombstoneEvent
EnableLoggingForZoneDataWriteEvent
EnableLoggingForZoneLoadingEvent

Note: The UseSystemEventLog does not have to be set to true if all other variables are logged per the requirement and it can be validated that the events are being logged to a different log file destination.                                                                     

Important: Debug logging can be resource intensive, affecting overall server performance and consuming disk space. Therefore, it should only be used temporarily when more detailed information about server performance is needed and should not be set to always enabled.                                                                                                                                                   

If all required diagnostic events are not set to "True", this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Open an elevated Windows PowerShell prompt on the DNS server to which event logging needs to be enabled.

Use the "Set-DnsServerDiagnostics" cmdlet to enable the required diagnostic events.

Set-DnsServerDiagnostics -<diagnostic event> $true <enter> for the required diagnostic events.

For example, to set EnableLoggingForLocalLookupEvent to true, enter the following at the command line:
Set-DnsServerDiagnostics -EnableLoggingForLocalLookupEvent $true <enter>'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16845r819714_chk'
  tag severity: 'medium'
  tag gid: 'V-215651'
  tag rid: 'SV-215651r819716_rule'
  tag stig_id: 'WDNS-AU-000006'
  tag gtitle: 'SRG-APP-000089-DNS-000005'
  tag fix_id: 'F-16843r819715_fix'
  tag 'documentable'
  tag legacy: ['SV-72981', 'V-58551']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
