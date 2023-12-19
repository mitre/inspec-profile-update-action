control 'SV-227555' do
  title 'The physical devices must not be assigned to non-global zones.'
  desc 'Solaris non-global zones can be assigned physical hardware devices.  This increases the risk of such a non-global zone having the capability to compromise the global zone.'
  desc 'check', 'If the system is not a global zone, this vulnerability is not applicable.
List the non-global zones on the system.
# zoneadm list -vi
List the configuration for each zone.
# zonecfg -z <zone> info
Check for device lines.  If such a line exists, this is a finding.'
  desc 'fix', 'Remove all device assignments from the non-global zone.
# zonecfg -z <zone> remove device <device>'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29717r488198_chk'
  tag severity: 'medium'
  tag gid: 'V-227555'
  tag rid: 'SV-227555r603266_rule'
  tag stig_id: 'GEN000000-SOL00660'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29705r488199_fix'
  tag 'documentable'
  tag legacy: ['V-22609', 'SV-27024']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
