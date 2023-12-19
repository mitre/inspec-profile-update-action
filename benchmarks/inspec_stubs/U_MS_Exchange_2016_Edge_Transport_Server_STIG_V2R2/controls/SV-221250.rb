control 'SV-221250' do
  title 'Exchange must have antispam filtering enabled.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2016 provides both antispam and antimalware protection out of the box. The Exchange 2016 antispam and antimalware product capabilities are limited but still provide some protection.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP) for an installed antispam product.

Note: If using another DoD-approved antispam product for email or a DoD-approved Email Gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), this is not applicable.

Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Format-Table Name, Enabled; Get-SenderFilterConfig | Format-Table Name, Enabled; Get-SenderIDConfig | Format-Table Name, Enabled; Get-SenderReputationConfig | Format-Table Name, Enabled

If any of the following values returned are not set to "True", this is a finding:

Set-ContentFilterConfig 
Set-SenderFilterConfig 
Set-SenderIDConfig 
Set-SenderReputationConfig'
  desc 'fix', 'Open the Exchange Management Shell and enter the following command for any values that were not set to True:

Set-ContentFilterConfig -Enabled $true

Set-SenderFilterConfig -Enabled $true

Set-SenderIDConfig -Enabled $true

Set-SenderReputationConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22965r411876_chk'
  tag severity: 'medium'
  tag gid: 'V-221250'
  tag rid: 'SV-221250r612603_rule'
  tag stig_id: 'EX16-ED-000540'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-22954r411877_fix'
  tag 'documentable'
  tag legacy: ['SV-95291', 'V-80581']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
