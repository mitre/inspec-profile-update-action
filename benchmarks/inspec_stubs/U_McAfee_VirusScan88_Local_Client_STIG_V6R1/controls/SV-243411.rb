control 'SV-243411' do
  title 'McAfee VirusScan On-Access Scanner General Settings Artemis Heuristic network check for suspicious files must be enabled and set to sensitivity level Medium or higher.'
  desc 'Antivirus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily antivirus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running antivirus software, since by querying the cloud-based database when a file appears to be suspicious, up-to-the-minute intelligence is provided. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates, and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by US CYBERCOM on DoD systems.'
  desc 'check', 'NOTE: For systems on the SIPRnet, this check is Not Applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the General tab, locate the "Artemis (Heuristic network check for suspicious files):" label. Ensure the Sensitivity level is set to "Medium" or higher.

Criteria:  If the Sensitivity level of "Medium", or higher, is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner

Criteria:  If the value of ArtemisEnabled is REG_DWORD = 0, this is a finding.
If the value of ArtemisLevel is REG_DWORD = 0 or REG_DWORD = 1, this is a finding.
If the value of ArtemisEnabled is REG_DWORD = 1 and the ArtemisLevel is REG_DWORD = 2, 3 or 4, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the General tab, locate the "Artemis (Heuristic network check for suspicious files):" label. Select the "Medium" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46686r722570_chk'
  tag severity: 'medium'
  tag gid: 'V-243411'
  tag rid: 'SV-243411r722572_rule'
  tag stig_id: 'DTAM137'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46643r722571_fix'
  tag 'documentable'
  tag legacy: ['V-42549', 'SV-55277']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
