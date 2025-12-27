control 'SV-216976' do
  title 'McAfee VirusScan On-Access Default Processes Policies actions, When an unwanted program is found must be configured to delete files automatically if first action fails.'
  desc 'Potentially Unwanted Programs (PUPs) include Spyware, Adware, Remote Administration Tools, Dialers, Password Crackers, Jokes, and Key Loggers. While PUPs do not typically have any infections capability on their own, they rely on malware or other attach mechanisms to be installed onto target hosts, after which they will collect and transfer data from the host to an external host and/or will be used as attach mechanisms. Configuring the antivirus software to attempt to clean the file first will allow for the possibility of a false positive. In most cases, however, the secondary action of delete will be used, mitigating the risk of the PUPs being installed and used maliciously.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. 

Under the Actions tab, locate the  "When an unwanted program is found:" label. Ensure the "If the first action fails, then perform this action:" has "Delete files automatically" selected.

Criteria:  If "Delete files automatically" is selected from the "If the first action fails, then perform this action:" drop-down list, this is not a finding.

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration\\Default

Criteria:  If the uSecAction_Program does not have a value of 4, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access Default Processes Policies. 

Under the Actions tab, locate the  "When an unwanted program is found:" label. From the "If the first action fails, then perform this action:" pull down menu, select "Delete files automatically".
Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18206r309657_chk'
  tag severity: 'medium'
  tag gid: 'V-216976'
  tag rid: 'SV-216976r397870_rule'
  tag stig_id: 'DTAM167'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18204r309658_fix'
  tag 'documentable'
  tag legacy: ['SV-55271', 'V-42543']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
