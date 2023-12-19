control 'SV-240469' do
  title 'The SLES for vRealize must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Check that the SLES for vRealize configured to use TCP syncookies when experiencing a TCP SYN flood.

# cat /proc/sys/net/ipv4/tcp_syncookies

If the result is not "1", this is a finding.'
  desc 'fix', "Configure the SLES for vRealize to use TCP syncookies when experiencing a TCP SYN flood.

# sed -i 's/^.*\\bnet.ipv4.tcp_syncookies\\b.*$/net.ipv4.tcp_syncookies=1/' /etc/sysctl.conf

Reload sysctl to verify the new change:

# sysctl -p"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43702r671146_chk'
  tag severity: 'medium'
  tag gid: 'V-240469'
  tag rid: 'SV-240469r671148_rule'
  tag stig_id: 'VRAU-SL-000785'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-43661r671147_fix'
  tag 'documentable'
  tag legacy: ['SV-100365', 'V-89715']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
