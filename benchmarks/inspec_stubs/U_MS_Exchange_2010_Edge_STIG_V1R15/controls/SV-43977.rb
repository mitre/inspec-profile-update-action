control 'SV-43977' do
  title 'SMTP Sender Filter must be enabled.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound Email evaluation can significantly reduce SPAM, PHISHING, and SPOOFED Emails. Messages from blank senders, known SPAMMERS, or 0-day attack modifications must be enabled to be effective. 

Failure to enable the filter will result in no action taken. This setting should always be enabled.'
  desc 'check', "This requirement is N/A for SIPR enclaves.  

This requirement is N/A if the organization subscribes to EEMSG or other similar DoD enterprise protections for email services.

Open the Exchange Management Shell and enter the following command:
 
Get-SenderFilterConfig | Select Enabled

If the value of 'Enabled' is not set to 'True', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-SenderfilterConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41663r2_chk'
  tag severity: 'medium'
  tag gid: 'V-33557'
  tag rid: 'SV-43977r2_rule'
  tag stig_id: 'Exch-2-336'
  tag gtitle: 'Exch-2-336'
  tag fix_id: 'F-37449r1_fix'
  tag 'documentable'
end
