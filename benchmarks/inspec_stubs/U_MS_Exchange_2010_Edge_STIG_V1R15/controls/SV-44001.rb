control 'SV-44001' do
  title 'Recipient filter must be enabled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound Email evaluation can significantly reduce SPAM, PHISHING, and SPOOFED Emails. Messages from blank senders, known SPAMMERS, or 0-day attack modifications must be enabled to be effective.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-RecipientFilterConfig | Select Enabled

If the value of 'Enabled' is not set to 'True', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-RecipientFilterConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41687r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33581'
  tag rid: 'SV-44001r1_rule'
  tag stig_id: 'Exch-2-743'
  tag gtitle: 'Exch-2-743'
  tag fix_id: 'F-37472r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
