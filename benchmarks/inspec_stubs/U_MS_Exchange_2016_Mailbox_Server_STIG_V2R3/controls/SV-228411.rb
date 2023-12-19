control 'SV-228411' do
  title 'Exchange must have the most current, approved service pack installed.'
  desc 'Failure to install the most current Exchange service pack leaves a system vulnerable to exploitation. Current service packs correct known security and system vulnerabilities.'
  desc 'check', 'Determine the most current, approved service pack.

Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer | fl Name, AdminDisplayVersion

If the value of "AdminDisplayVersion" does not return the most current, approved service pack, this is a finding.'
  desc 'fix', 'Install the most current, approved service pack.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30644r497029_chk'
  tag severity: 'medium'
  tag gid: 'V-228411'
  tag rid: 'SV-228411r612748_rule'
  tag stig_id: 'EX16-MB-000680'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-30629r497030_fix'
  tag 'documentable'
  tag legacy: ['SV-95451', 'V-80741']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
