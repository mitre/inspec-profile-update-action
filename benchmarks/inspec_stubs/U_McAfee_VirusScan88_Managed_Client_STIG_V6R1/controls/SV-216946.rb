control 'SV-216946' do
  title 'McAfee VirusScan Unwanted Programs Policies must be configured to detect adware.'
  desc 'Adware, like spyware, is, at best, an annoyance by presenting unwanted advertisement to the user of a computer, sometimes in the form of a popup.  At worst, it redirects the user to malicious websites. Detecting and blocking will mitigate the likelihood of users being tricked into visiting sites with malicious content.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Unwanted Programs Policies. Under the Scan Items tab, locate the "Select categories of unwanted programs to detect:" label. Ensure the "Adware" option is selected.

Criteria:  If the "Adware" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\NVP

Criteria:  If the value DetectAdware is 1, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Unwanted Programs Policies. Under the Scan Items tab, locate the "Select categories of unwanted programs to detect:" label. Select the "Adware" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18176r309567_chk'
  tag severity: 'medium'
  tag gid: 'V-216946'
  tag rid: 'SV-216946r397873_rule'
  tag stig_id: 'DTAM136'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-18174r309568_fix'
  tag 'documentable'
  tag legacy: ['SV-55242', 'V-14663']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
