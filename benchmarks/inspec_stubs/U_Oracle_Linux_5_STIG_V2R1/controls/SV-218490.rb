control 'SV-218490' do
  title 'The system must not be configured for network bridging.'
  desc 'Some systems have the ability to bridge or switch frames (link-layer forwarding) between multiple interfaces.  This can be useful in a variety of situations but, if enabled when not needed, has the potential to bypass network partitioning and security.'
  desc 'check', "Verify the system is not configured for bridging.
# ls /proc/sys/net/bridge
If the directory exists, this is a finding.
# lsmod | grep '^bridge '
If any results are returned, this is a finding.

Fix Text: Configure the system to not use bridging."
  desc 'fix', 'Configure the system to not use bridging.
# rmmod bridge
Edit /etc/modprobe.conf and add a line such as "install bridge /bin/false" to prevent the loading of the bridge module.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19965r562606_chk'
  tag severity: 'medium'
  tag gid: 'V-218490'
  tag rid: 'SV-218490r603259_rule'
  tag stig_id: 'GEN003619'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-19963r562607_fix'
  tag 'documentable'
  tag legacy: ['V-22421', 'SV-64213']
  tag cci: ['CCI-000381', 'CCI-001551']
  tag nist: ['CM-7 a', 'AC-4']
end
