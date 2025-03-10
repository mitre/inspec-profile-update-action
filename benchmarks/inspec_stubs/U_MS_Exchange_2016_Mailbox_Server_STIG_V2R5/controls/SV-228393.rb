control 'SV-228393' do
  title 'Exchange must have anti-spam filtering installed.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2016 provides both anti-spam and anti-malware protection out of the box. The Exchange 2016 anti-spam and anti-malware product capabilities are limited but still provide some protection.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Note: If using another DoD-approved antispam product for email or a DoD-approved email gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), this is not applicable (NA).

Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Format-Table Name,Enabled

If no value is returned, this is a finding.'
  desc 'fix', 'Update the EDSP with the anti-spam mechanism used.

Install the AntiSpam module. 

Open the Exchange Management Shell and enter the following command:

& $env:ExchangeInstallPath\\Scripts\\Install-AntiSpamAgents.ps1'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30626r496975_chk'
  tag severity: 'medium'
  tag gid: 'V-228393'
  tag rid: 'SV-228393r879653_rule'
  tag stig_id: 'EX16-MB-000490'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30611r496976_fix'
  tag 'documentable'
  tag legacy: ['SV-95411', 'V-80701']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
