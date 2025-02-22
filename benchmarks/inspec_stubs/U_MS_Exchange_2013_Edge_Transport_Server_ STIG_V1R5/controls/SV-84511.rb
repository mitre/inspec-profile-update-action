control 'SV-84511' do
  title 'The Exchange Recipient filter must be enabled.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound email evaluation can significantly reduce spam, phishing, and spoofed emails. Messages from blank senders, known spammers, or zero-day attack modifications must be enabled to be effective.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-RecipientFilterConfig | Select Name, Enabled

If the value of Enabled is not set to True, this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-RecipientFilterConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70357r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69889'
  tag rid: 'SV-84511r1_rule'
  tag stig_id: 'EX13-EG-000235'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76119r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
