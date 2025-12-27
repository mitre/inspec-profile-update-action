control 'SV-1085' do
  title 'Floppy media devices are not allocated upon user logon.'
  desc 'This check verifies that Windows is configured to not limit access to floppy drives when a user is logged on locally per the FDCC.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  Expand the Security Configuration and Analysis tree view.

Navigate to Local Policies -> Security Options.
If the value for “Devices: Restrict floppy access to locally logged-on user only” is not set to “Disabled”, then this is a finding.

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Subkey: \\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\

Value Name: Allocatefloppies

Value Type:  REG_SZ
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Restrict floppy access to locally logged-on user only” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-44r1_chk'
  tag severity: 'low'
  tag gid: 'V-1085'
  tag rid: 'SV-1085r1_rule'
  tag gtitle: 'Removable media devices - Floppies'
  tag fix_id: 'F-70r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECSC-1'
end
