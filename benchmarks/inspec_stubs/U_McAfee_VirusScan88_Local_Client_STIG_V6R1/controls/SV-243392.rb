control 'SV-243392' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to block the connection when a threatened file is detected in a shared folder.'
  desc 'Containment during a virus outbreak is crucial. Infected hosts may attempt to spread malware and will use every network path available to them when spreading that infection. By containing the system when a detection is found, the malware will be restricted to that one system. Likewise, if malware is detected in a shared folder, maintaining the connection between a system and the shared folder would allow the malware to spread. Placing temporary restrictions on network connectivity is an effective mitigation mechanism. 

These block connection settings will most often be used on a server housing shared folders and files, and will block the connection from any network user on a remote computer who attempts to read from, or write to, a threatened file in the shared folder. In addition, it will block the connection from any user on a remote computer who attempts to write an unwanted program to the computer. The connection will be unblocked after the specified amount of time, re-allowing access to the other shared files and folders, but will be re-blocked should those same file accesses be attempted.'
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Blocking tab, locate the "Block" label. Ensure the "Block the connection when a threat is detected in a shared folder" option is selected.

Criteria:  If the "Block the connection when a threat is detected in a shared folder" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value of VSIDBlock is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Blocking tab, locate the "Block" label. Select the "Block the connection when a threat is detected in a shared folder" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8-8 Local Client'
  tag check_id: 'C-46667r722513_chk'
  tag severity: 'medium'
  tag gid: 'V-243392'
  tag rid: 'SV-243392r722515_rule'
  tag stig_id: 'DTAM091'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-46624r722514_fix'
  tag 'documentable'
  tag legacy: ['V-14618', 'SV-56400']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
