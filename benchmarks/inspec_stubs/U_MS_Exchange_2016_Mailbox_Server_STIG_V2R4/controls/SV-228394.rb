control 'SV-228394' do
  title 'Exchange must have anti-spam filtering enabled.'
  desc 'Originators of spam messages are constantly changing their techniques in order to defeat spam countermeasures; therefore, spam software must be constantly updated to address the changing threat. A manual update procedure is labor intensive and does not scale well in an enterprise environment. This risk may be mitigated by using an automatic update capability. Spam protection mechanisms include, for example, signature definitions, rule sets, and algorithms.

Exchange 2016 provides both anti-spam and anti-malware protection out of the box. The Exchange 2016 anti-spam and anti-malware product capabilities are limited but still provide some protection.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Note: If using another DoD-approved anti-spam product for email or a DoD-approved email gateway spamming device, such as Enterprise Email Security Gateway (EEMSG), this is not applicable (NA).

Open the Exchange Management Shell and enter the following command:

Get-ContentFilterConfig | Format-Table Name,Enabled; Get-SenderFilterConfig | Format-Table Name,Enabled; Get-SenderIDConfig | Format-Table Name,Enabled; Get-SenderReputationConfig | Format-Table Name,Enabled

If any of the following values returned are not set to "True", this is a finding:

Set-ContentFilterConfig 
Set-SenderFilterConfig 
Set-SenderIDConfig
Set-SenderReputationConfig'
  desc 'fix', 'Update the EDSP with the anti-spam mechanism used.

Open the Exchange Management Shell and enter the following command for any values that were not set to "True":

Set-ContentFilterConfig -Enabled $true

Set-SenderFilterConfig -Enabled $true

Set-SenderIDConfig -Enabled $true

Set-SenderReputationConfig -Enabled $true'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30627r496978_chk'
  tag severity: 'medium'
  tag gid: 'V-228394'
  tag rid: 'SV-228394r612748_rule'
  tag stig_id: 'EX16-MB-000500'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-30612r496979_fix'
  tag 'documentable'
  tag legacy: ['SV-95413', 'V-80703']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
