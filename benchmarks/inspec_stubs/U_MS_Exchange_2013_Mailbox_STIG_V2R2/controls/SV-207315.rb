control 'SV-207315' do
  title 'Exchange must have antispam filtering installed.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2013 provides both antispam and antimalware protection out of the box. The Exchange 2013 antispam and antimalware product capabilities are limited but still provide some protection.'
  desc 'check', 'Update the EDSP.

Note: If using another DoD-approved antispam product for email or a DoD-approved email gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), this is not applicable.

Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Format-Table Name,Enabled   

If no value is returned, this is a finding.'
  desc 'fix', 'Update the EDSP.

Install the AntiSpam module. 

Open the Exchange Management Shell and enter the following command:

& $env:ExchangeInstallPath\\Scripts\\Install-AntiSpamAgents.ps1'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7573r393458_chk'
  tag severity: 'medium'
  tag gid: 'V-207315'
  tag rid: 'SV-207315r615936_rule'
  tag stig_id: 'EX13-MB-000245'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-7573r393459_fix'
  tag 'documentable'
  tag legacy: ['SV-84659', 'V-70037']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
