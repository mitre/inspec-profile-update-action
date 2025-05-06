control 'SV-84521' do
  title 'The Exchange Simple Mail Transfer Protocol (SMTP) Sender filter must be enabled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound email evaluation can significantly reduce spam, phishing, and spoofed emails. Filters for messages from blank senders, known spammers, or zero-day attack modifications must be enabled to be effective. 

Failure to enable the filter will result in no action taken. This setting should always be enabled.'
  desc 'check', 'This requirement is N/A for SIPR enclaves.

This requirement is N/A if the organization subscribes to EEMSG or other similar DoD enterprise protections for email services.

Open the Exchange Management Shell and enter the following command:
 
Get-SenderFilterConfig | Select Name, Enabled

If the value of Enabled is not set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderfilterConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70367r2_chk'
  tag severity: 'medium'
  tag gid: 'V-69899'
  tag rid: 'SV-84521r2_rule'
  tag stig_id: 'EX13-EG-000260'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76129r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
