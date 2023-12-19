control 'SV-1085' do
  title 'Floppy media devices are not allocated upon user logon.'
  desc 'This check verifies that Windows is configured to not limit access to floppy drives when a user is logged on locally per the FDCC.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “Devices: Restrict floppy access to locally logged-on user only” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-1085'
  tag rid: 'SV-1085r1_rule'
  tag gtitle: 'Removable media devices - Floppies'
  tag fix_id: 'F-70r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1, ECSC-1'
end
