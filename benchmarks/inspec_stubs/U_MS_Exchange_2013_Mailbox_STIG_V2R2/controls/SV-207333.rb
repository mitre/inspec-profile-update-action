control 'SV-207333' do
  title 'Exchange must have the most current, approved service pack installed.'
  desc 'Failure to install the most current Exchange service pack leaves a system vulnerable to exploitation. Current service packs correct known security and system vulnerabilities.'
  desc 'check', 'Determine the most current, approved service pack.

Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer | fl Name, AdminDisplayVersion

If the value of AdminDisplayVersion does not return the most current, approved service pack, this is a finding.'
  desc 'fix', 'Install the most current, approved service pack.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7591r393512_chk'
  tag severity: 'medium'
  tag gid: 'V-207333'
  tag rid: 'SV-207333r615936_rule'
  tag stig_id: 'EX13-MB-000340'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-7591r393513_fix'
  tag 'documentable'
  tag legacy: ['SV-84681', 'V-70059']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
