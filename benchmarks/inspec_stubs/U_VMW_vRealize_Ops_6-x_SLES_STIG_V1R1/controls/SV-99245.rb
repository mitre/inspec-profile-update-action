control 'SV-99245' do
  title 'The SLES for vRealize must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Check that SLES for vRealize is configured to use TCP syncookies when experiencing a TCP SYN flood.

# cat /proc/sys/net/ipv4/tcp_syncookies

If the result is not "1", this is a finding.'
  desc 'fix', "Configure SLES for vRealize to use TCP syncookies when experiencing a TCP SYN flood.

# sed -i 's/^.*\\bnet.ipv4.tcp_syncookies\\b.*$/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf

Reload sysctl to verify the new change:

# sysctl -p"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88287r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88595'
  tag rid: 'SV-99245r1_rule'
  tag stig_id: 'VROM-SL-000760'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-95337r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
