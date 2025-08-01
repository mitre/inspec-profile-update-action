control 'SV-56406' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to unblock connections after a minimum of 30 minutes.'
  desc 'Containment during a virus outbreak is crucial. Infected hosts may attempt to spread malware and will use every network path available to them when spreading that infection. By containing the system when a detection is found, the malware will be restricted to that one system. Likewise, if malware is detected in a shared folder, maintaining the connection between a system and the shared folder would allow the malware to spread. Placing temporary restrictions on network connectivity is an effective mitigation mechanism. 

These block connection settings will most often be used on a server housing shared folders and files, and will block the connection from any network user on a remote computer who attempts to read from, or write to, a threatened file in the shared folder. In addition, it will block the connection from any user on a remote computer who attempts to write an unwanted program to the computer. The connection will be unblocked after the specified amount of time, re-allowing access to the other shared files and folders, but will be re-blocked should those same file accesses be attempted.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Blocking tab, locate the "Block" label. Ensure the "Unblock connections after (minutes)" is set to no less than 30 minutes.

Criteria:  If the "Unblock connections after (minutes)" option is configured to no less than 30 minutes, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of VSIDBlockTimeout >= to HEX 1E, this is not a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Blocking tab, locate the "Block" label. Enter a value in "Unblock connections after (minutes)" where x is set to no less than 30 minutes. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49330r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14620'
  tag rid: 'SV-56406r1_rule'
  tag stig_id: 'DTAM092'
  tag gtitle: 'DTAM092-McAfee VirusScan on-access scan blocking'
  tag fix_id: 'F-49134r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
