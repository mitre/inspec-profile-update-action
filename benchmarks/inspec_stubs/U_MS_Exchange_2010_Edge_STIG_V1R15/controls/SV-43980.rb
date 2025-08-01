control 'SV-43980' do
  title 'SMTP IP Allow List entries must be empty.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound Email evaluation can significantly reduce SPAM, PHISHING, and SPOOFED Emails. Messages from blank senders, known SPAMMERS, or 0-day attack modifications must be enabled to be effective. 

Having items identified in the ‘allow’ list causes other SPAM evaluation steps to be bypassed, and therefore should be used only with an abundance of caution.  If SPAMMERS were to learn of entries in the ‘allow list’ it could enable them to plan a denial of service attack (or other attack) by spoofing that source.'
  desc 'check', 'Access the EDSP and identify the SMTP ‘allow list’ settings. 

Open the Exchange Management Shell and enter the following command:

Get-IPAllowListEntry | fl
 
If the result returns any values, this is a finding.
If the result returns any values, but has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Open the Exchange Management Shell and noting identifiers from above, enter the following command:

Remove-IPAllowListEntry -Identity <IP Allow List entry ID>'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41666r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33560'
  tag rid: 'SV-43980r1_rule'
  tag stig_id: 'Exch-2-342'
  tag gtitle: 'Exch-2-342'
  tag fix_id: 'F-37452r1_fix'
  tag 'documentable'
end
