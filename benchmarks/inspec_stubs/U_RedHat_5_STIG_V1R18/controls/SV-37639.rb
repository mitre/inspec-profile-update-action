control 'SV-37639' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36836r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22421'
  tag rid: 'SV-37639r1_rule'
  tag stig_id: 'GEN003619'
  tag gtitle: 'GEN003619'
  tag fix_id: 'F-31674r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
