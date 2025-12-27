control 'SV-84517' do
  title 'Exchange Simple Mail Transfer Protocol (SMTP) IP Allow List entries must be empty.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Careful tuning reduces the risk that system or network congestion will contribute to availability impacts. 

Filters that govern inbound email evaluation can significantly reduce spam, phishing, and spoofed emails. Filters for messages from blank senders, known spammers, or zero-day attack modifications must be enabled to be effective. 

Having items identified in the Allow List causes other spam evaluation steps to be bypassed and therefore should be used only with an abundance of caution. If spammers were to learn of entries in the Allow List, it could enable them to plan a denial of service attack (or other attack) by spoofing that source.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Identify the SMTP allow list settings. 

Open the Exchange Management Shell and enter the following command:

Get-IPAllowListEntry | fl
 
If the result returns any values, this is a finding.   

or 

If the result returns any values but has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', 'Update the EDSP.

Open the Exchange Management Shell and enter the following command:

Note: Remove any value(s) that are not identified by the EDSP or have not obtained a signoff with risk acceptance.

Remove-IPAllowListEntry -Identity <IP Allow List entry ID>'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70363r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69895'
  tag rid: 'SV-84517r1_rule'
  tag stig_id: 'EX13-EG-000250'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-76125r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
