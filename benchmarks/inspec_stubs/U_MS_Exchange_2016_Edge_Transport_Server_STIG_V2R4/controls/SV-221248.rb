control 'SV-221248' do
  title 'The Exchange Simple Mail Transfer Protocol (SMTP) Sender filter must be enabled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound email evaluation can significantly reduce spam, phishing, and spoofed emails. Filters for messages from blank senders, known spammers, or zero-day attack modifications must be enabled to be effective. 

Failure to enable the filter will result in no action taken. This setting should always be enabled.'
  desc 'check', 'This requirement is N/A for SIPR enclaves.  

This requirement is N/A if the organization subscribes to EEMSG or other similar DoD enterprise protections for email services.

Open the Exchange Management Shell and enter the following command:
 
Get-SenderFilterConfig | Select Name, Enabled

If the value of "Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderFilterConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22963r411870_chk'
  tag severity: 'medium'
  tag gid: 'V-221248'
  tag rid: 'SV-221248r612603_rule'
  tag stig_id: 'EX16-ED-000520'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22952r411871_fix'
  tag 'documentable'
  tag legacy: ['SV-95287', 'V-80577']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
