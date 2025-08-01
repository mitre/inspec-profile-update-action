control 'SV-207317' do
  title 'Exchange must have antispam filtering configured.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2013 provides both antispam and antimalware protection out of the box. The Exchange 2013 antispam and antimalware product capabilities are limited but still provide some protection.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Note: If using another DoD-approved antispam product for email or a DoD-approved email gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), this is not applicable.

Determine the Internal SMTP servers. 

Open the Exchange Management Shell and enter the following command:

Get-TransportConfig | Format-List InternalSMTPServers

If any internal SMTP server IP address returned does not reflect the list of accepted SMTP server IPs, this is a finding.'
  desc 'fix', "Note: Configure the IP addresses of every internal SMTP server. If the Mailbox server is the only SMTP server running the antispam agents, configure the IP address of the Mailbox server. 

Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Single SMTP server address:

Set-TransportConfig -InternalSMTPServers @{Add='<ip address1>'}

Multiple SMTP server addresses:

Set-TransportConfig -InternalSMTPServers @{Add='<ip address1>','<ip address2>'}"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7575r393464_chk'
  tag severity: 'medium'
  tag gid: 'V-207317'
  tag rid: 'SV-207317r615936_rule'
  tag stig_id: 'EX13-MB-000255'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-7575r393465_fix'
  tag 'documentable'
  tag legacy: ['SV-84663', 'V-70041']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
