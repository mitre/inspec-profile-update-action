control 'SV-55241' do
  title 'McAfee VirusScan Unwanted Programs Policies must be configured to detect spyware.'
  desc "Spyware is software that aids in gathering information about a person or organization without their knowledge, and that may send such information to another entity without the consumer's consent, or that asserts control over a computer without the user's knowledge. Spyware may try to deceive users by bundling itself with desirable software. A spyware infestation can create significant unwanted CPU activity, disk usage, and network traffic. Some types of spyware disable software firewalls and antivirus software. Detecting, blocking, and eradicating malicious spyware or preventing it from being installed will alleviate the negative side effects of the spyware."
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Unwanted Programs Policies. Under the Scan Items tab, locate the "Select categories of unwanted programs to detect:" label. Ensure the "Spyware" option is selected.

Criteria:  If the "Spyware" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\NVP

Criteria:  If the value DetectSpyware is 1, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select the policy associated with the Unwanted Programs Policies. Under the Scan Items tab, locate the "Select categories of unwanted programs to detect:" label. Select the "Spyware" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48830r2_chk'
  tag severity: 'medium'
  tag gid: 'V-14662'
  tag rid: 'SV-55241r1_rule'
  tag stig_id: 'DTAM135'
  tag gtitle: 'DTAM135-McAfee VirusScan detection of Spyware'
  tag fix_id: 'F-48095r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
