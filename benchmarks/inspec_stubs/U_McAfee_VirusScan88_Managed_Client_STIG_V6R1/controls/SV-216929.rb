control 'SV-216929' do
  title 'McAfee VirusScan On-Access General Policies must be configured to unblock connections after a minimum of 30 minutes.'
  desc 'Containment during a virus outbreak is crucial. Infected hosts may attempt to spread malware and will use every network path available to them when spreading that infection. By containing the system when a detection is found, the malware will be restricted to that one system. Likewise, if malware is detected in a shared folder, maintaining the connection between a system and the shared folder would allow the malware to spread. Placing temporary restrictions on network connectivity is an effective mitigation mechanism. 

These block connection settings will most often be used on a server housing shared folders and files, and will block the connection from any network user on a remote computer who attempts to read from, or write to, a threatened file in the shared folder. In addition, it will block the connection from any user on a remote computer who attempts to write an unwanted program to the computer. The connection will be unblocked after the specified amount of time, re-allowing access to the other shared files and folders, but will be re-blocked should those same file accesses be attempted.'
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Blocking tab, locate the "Block the connection:" label. Ensure the "Unblock connections after x minutes" option has x set to no less than 30 minutes.

Criteria: If the "Unblock connections after x minute(s)" option is configured to no less than 30 minutes, this is not a finding.  

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of VSIDBlockTimeout >= to HEX 1E, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Blocking tab, locate the "Block the connection:" label. Enter a value in "Unblock connections after x minutes" where x is set to no less than 30 minutes. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18159r309516_chk'
  tag severity: 'medium'
  tag gid: 'V-216929'
  tag rid: 'SV-216929r397870_rule'
  tag stig_id: 'DTAM092'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-18157r309517_fix'
  tag 'documentable'
  tag legacy: ['SV-55219', 'V-14620']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
