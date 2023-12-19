control 'SV-221249' do
  title 'Exchange must have antispam filtering installed.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2016 provides both antispam and antimalware protection out of the box. The Exchange 2016 antispam and antimalware product capabilities are limited but still provide some protection.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) for an installed antispam product.

Note: If using another DoD-approved antispam product for email or a DoD-approved Email Gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), this is not applicable.

Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Format-Table Name, Enabled   

If no value is returned, this is a finding.'
  desc 'fix', 'Install the AntiSpam module. 

Open the Exchange Management Shell and enter the following command:

& $env:ExchangeInstallPath\\Scripts\\Install-AntiSpamAgents.ps1'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22964r411873_chk'
  tag severity: 'medium'
  tag gid: 'V-221249'
  tag rid: 'SV-221249r612603_rule'
  tag stig_id: 'EX16-ED-000530'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22953r411874_fix'
  tag 'documentable'
  tag legacy: ['V-80579', 'SV-95289']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
