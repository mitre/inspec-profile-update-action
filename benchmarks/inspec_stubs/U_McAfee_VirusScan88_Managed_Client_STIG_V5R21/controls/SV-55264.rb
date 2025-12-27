control 'SV-55264' do
  title 'McAfee VirusScan On-Delivery Email Scan Policies Artemis sensitivity level must be configured to medium or higher.'
  desc 'Antivirus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily antivirus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running antivirus software, since by querying the cloud-based database when a file appears to be suspicious, up-to-the-minute intelligence is provided. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates, and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by US CYBERCOM on DoD systems.'
  desc 'check', 'Note: For systems on the SIPRNet, this check is Not Applicable.

Note: If an email client is not running on this system, this check can be marked as Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Scan Items tab, locate the "Artemis (Heuristic network check for suspicious files):" label. Ensure the Sensitivity level is set to "Medium" or higher.

Criteria:  If the Sensitivity level is set to "Medium" or higher, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\Email Scanner

Criteria:  If the value of ArtemisEnabled is REG_DWORD = 0, this is a finding.
If the value of ArtemisLevel is REG_DWORD = 0 or REG_DWORD = 1, this is a finding.
If the value of ArtemisEnabled is REG_DWORD = 1 and the ArtemisLevel is REG_DWORD = 2, 3 or 4, this is not a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On Delivery Email Scan Policies. Under the Scan Items tab, locate the "Artemis (Heuristic network check for suspicious files):" label. Select the "Medium" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48854r6_chk'
  tag severity: 'medium'
  tag gid: 'V-42536'
  tag rid: 'SV-55264r2_rule'
  tag stig_id: 'DTAM157'
  tag gtitle: 'DTAM157-McAfee VirusScan Email on-delivery Artemis sensitivity level'
  tag fix_id: 'F-48118r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
