control 'SV-228395' do
  title 'Exchange must have anti-spam filtering configured.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2016 provides both anti-spam and anti-malware protection out of the box. The Exchange 2016 anti-spam and anti-malware product capabilities are limited but still provide some protection.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Note: If using another DoD-approved antispam product for email or a DoD-approved email gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), this is not applicable (NA).

Determine the internal SMTP servers. 

Open the Exchange Management Shell and enter the following command:

Get-TransportConfig | Format-List InternalSMTPServers

If any internal SMTP server IP address returned does not reflect the list of accepted SMTP server IP addresses, this is a finding.'
  desc 'fix', "Note: Configure the IP addresses of every internal SMTP server. If the Mailbox server is the only SMTP server running the antispam agents, configure the IP address of the Mailbox server. 

Update the EDSP with the anti-spam mechanism used.

Open the Exchange Management Shell and enter the following command:

Single SMTP server address:

Set-TransportConfig -InternalSMTPServers @{Add='<ip address1>'}

Multiple SMTP server addresses:

Set-TransportConfig -InternalSMTPServers @{Add='<ip address1>','<ip address2>'}"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30628r496981_chk'
  tag severity: 'medium'
  tag gid: 'V-228395'
  tag rid: 'SV-228395r612748_rule'
  tag stig_id: 'EX16-MB-000510'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30613r496982_fix'
  tag 'documentable'
  tag legacy: ['SV-95415', 'V-80705']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
