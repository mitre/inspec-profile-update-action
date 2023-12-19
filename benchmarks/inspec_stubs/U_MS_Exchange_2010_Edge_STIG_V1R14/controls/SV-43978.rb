control 'SV-43978' do
  title 'SMTP IP Allow List Connection Filter must be enabled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound Email evaluation can significantly reduce SPAM, PHISHING, and SPOOFED Emails. Messages from blank senders, known SPAMMERS, or 0-day attack modifications must be enabled to be effective. 

Having items identified in the ‘allow’ list causes other SPAM evaluation steps to be bypassed, and therefore should be used only with an abundance of caution.  If SPAMMERS were to learn of entries in the ‘allow list’ it could enable them to plan a denial of service attack (or other attack) by spoofing that source.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-IPAllowListConfig | fl
 
If the value for “Enabled” is set to “True” this is not a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:
Set-IPAllowListConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41664r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33558'
  tag rid: 'SV-43978r1_rule'
  tag stig_id: 'Exch-2-339'
  tag gtitle: 'Exch-2-339'
  tag fix_id: 'F-37450r1_fix'
  tag 'documentable'
end
