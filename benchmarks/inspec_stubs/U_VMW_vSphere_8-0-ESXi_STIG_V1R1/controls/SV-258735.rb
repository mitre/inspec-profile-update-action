control 'SV-258735' do
  title 'The ESXi host must prohibit password reuse for a minimum of five generations.'
  desc "If a user or root used the same password continuously or was allowed to change it back shortly after being forced to change it to something else, it would provide a potential intruder with the opportunity to keep guessing at one user's password until it was guessed correctly."
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Security.PasswordHistory" value and verify it is set to "5" or greater.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory

If the "Security.PasswordHistory" setting is set to a value other than 5 or greater, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Security.PasswordHistory" value and configure it to "5".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 5'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62475r933264_chk'
  tag severity: 'medium'
  tag gid: 'V-258735'
  tag rid: 'SV-258735r933266_rule'
  tag stig_id: 'ESXI-80-000043'
  tag gtitle: 'SRG-OS-000077-VMM-000440'
  tag fix_id: 'F-62384r933265_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
