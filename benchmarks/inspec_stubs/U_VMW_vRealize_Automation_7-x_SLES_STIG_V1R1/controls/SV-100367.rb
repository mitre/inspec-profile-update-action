control 'SV-100367' do
  title 'The SLES for vRealize must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Check that the SLES for vRealize has an appropriate TCP backlog queue size to mitigate against TCP SYN flood DOS attacks with the following command:

# cat /proc/sys/net/ipv4/tcp_max_syn_backlog

If the TCP backlog queue size is not set to at least the recommended default setting of "1280", this is a finding.'
  desc 'fix', "Configure the TCP backlog queue size with the following command:

# sed -i 's/^.*\\bnet.ipv4.tcp_max_syn_backlog\\b.*$/net.ipv4.tcp_max_syn_backlog=1280/' /etc/sysctl.conf

Reload sysctl to verify the new change:

# sysctl -p"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89717'
  tag rid: 'SV-100367r1_rule'
  tag stig_id: 'VRAU-SL-000790'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-96459r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
