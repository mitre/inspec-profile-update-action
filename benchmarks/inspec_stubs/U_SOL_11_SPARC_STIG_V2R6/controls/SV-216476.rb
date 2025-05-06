control 'SV-216476' do
  title 'The systems physical devices must not be assigned to non-global zones.'
  desc 'Solaris non-global zones can be assigned physical hardware devices. This increases the risk of such a non-global zone having the capability to compromise the global zone.'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

List the non-global zones on the system.

# zoneadm list -vi | grep -v global

List the configuration for each zone.

# zonecfg -z [zonename] info | grep dev

Check for device lines. If such a line exists and is not approved by security, this is a finding.'
  desc 'fix', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

The Zone Security profile is required:

Remove all device assignments from the non-global zone. 

# pfexec zonecfg -z [zone] delete device [device]'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17712r371510_chk'
  tag severity: 'medium'
  tag gid: 'V-216476'
  tag rid: 'SV-216476r603267_rule'
  tag stig_id: 'SOL-11.1-100030'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17710r371511_fix'
  tag 'documentable'
  tag legacy: ['SV-60715', 'V-47841']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
