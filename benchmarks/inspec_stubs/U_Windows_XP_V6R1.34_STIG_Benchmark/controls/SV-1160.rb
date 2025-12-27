control 'SV-1160' do
  title 'The unsigned driver installation behavior is improperly set.'
  desc 'Determines what should happen when an attempt is made to install a device driver (by means of the Windows device installer) that has not been certified by the Windows Hardware Quality Lab (WHQL).

The options are:
- Silently succeed
- Warn but allow installation
- Do not allow installation'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Unsigned driver installation behavior” to “Warn but allow installation” or “Do not allow installation”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1160'
  tag rid: 'SV-1160r1_rule'
  tag gtitle: 'Unsigned Driver Installation Behavior'
  tag fix_id: 'F-109r1_fix'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'DCSL-1'
end
