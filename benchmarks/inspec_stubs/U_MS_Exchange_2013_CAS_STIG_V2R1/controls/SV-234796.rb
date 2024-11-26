control 'SV-234796' do
  title 'Exchange must have the most current, approved service pack installed.'
  desc 'Failure to install the most current Exchange service pack leaves a system vulnerable to exploitation. Current service packs correct known security and system vulnerabilities.'
  desc 'check', 'Determine the most current, approved service pack.

Open the Exchange Management Shell and enter the following command:

Get-ExchangeServer | fl Name, AdminDisplayVersion

For each Name from the previous command, enter the following command:

Invoke-Command -ComputerName [Name] -ScriptBlock {Get-Command Exsetup.exe | ForEach-Object {$_.FileversionInfo}}

If the version displayed does not reflect the most current, approved service pack, this is a finding.'
  desc 'fix', 'Install the most current, approved service pack.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37982r811164_chk'
  tag severity: 'medium'
  tag gid: 'V-234796'
  tag rid: 'SV-234796r811165_rule'
  tag stig_id: 'EX13-CA-000160'
  tag gtitle: 'SRG-APP-000456'
  tag fix_id: 'F-37945r617328_fix'
  tag 'documentable'
  tag legacy: ['SV-84401', 'V-69779']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
