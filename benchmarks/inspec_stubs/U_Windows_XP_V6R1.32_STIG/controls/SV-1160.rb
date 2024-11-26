control 'SV-1160' do
  title 'The unsigned driver installation behavior is improperly set.'
  desc 'Determines what should happen when an attempt is made to install a device driver (by means of the Windows device installer) that has not been certified by the Windows Hardware Quality Lab (WHQL).

The options are:
- Silently succeed
- Warn but allow installation
- Do not allow installation'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies -> Security Options.

If the value for “Devices: Unsigned driver installation behavior” is not set to “Warn but allow installation” or “Do not allow installation”, then this is a finding.
 
 The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\Software\\Microsoft\\Driver Signing\\

Value Name:  Policy

Value Type:  REG_BINARY
Value:  1 (Warn but allow installation), 2 (Do not allow installation)

Documentable Explanation: If the site is using a Software Update Server (SUS) server to distribute software updates, and the computer is configured to point at that server, then this can be set to "Silently succeed" to allow unattended installation of distributed updates. To determine if an SUS server is used, see if the following registry key value exists and is pointing to an organizational or DOD SUS URL: 

HKLM\\Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer, Reg_SZ: http://…'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Unsigned driver installation behavior” to “Warn but allow installation” or “Do not allow installation”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-128r1_chk'
  tag severity: 'low'
  tag gid: 'V-1160'
  tag rid: 'SV-1160r1_rule'
  tag gtitle: 'Unsigned Driver Installation Behavior'
  tag fix_id: 'F-109r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCSL-1'
end
