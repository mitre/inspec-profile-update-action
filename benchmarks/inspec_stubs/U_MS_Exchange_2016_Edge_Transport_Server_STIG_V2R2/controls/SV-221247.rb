control 'SV-221247' do
  title 'The Exchange Simple Mail Transfer Protocol (SMTP) IP Allow List Connection filter must be enabled.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound email evaluation can significantly reduce spam, phishing, and spoofed emails. Filters for messages from blank senders, known spammers, or zero-day attack modifications must be enabled to be effective. 

Having items identified in the Allow List causes other spam evaluation steps to be bypassed and therefore should be used only with an abundance of caution. If spammers were to learn of entries in the Allow List, it could enable them to plan a denial of service attack (or other attack) by spoofing that source.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-IPAllowListConfig | Select Name, Enabled
 
If the value for "Enabled" is not set to "True", this is a finding.'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-IPAllowListConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22962r411867_chk'
  tag severity: 'medium'
  tag gid: 'V-221247'
  tag rid: 'SV-221247r612603_rule'
  tag stig_id: 'EX16-ED-000510'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22951r411868_fix'
  tag 'documentable'
  tag legacy: ['SV-95285', 'V-80575']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
