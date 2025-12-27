control 'SV-99247' do
  title 'The SLES for vRealize must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Check that SLES for vRealize has an appropriate TCP backlog queue size to mitigate against TCP SYN flood DOS attacks with the following command:

# cat /proc/sys/net/ipv4/tcp_max_syn_backlog

The recommended default setting is "1280". 

If the TCP backlog queue size is not set to "1280", this is a finding.'
  desc 'fix', "Configure the TCP backlog queue size with the following command:

# sed -i 's/^.*\\bnet.ipv4.tcp_max_syn_backlog\\b.*$/net.ipv4.tcp_max_syn_backlog=1280/' /etc/sysctl.conf

Reload sysctl to verify the new change:

# sysctl -p"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88289r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88597'
  tag rid: 'SV-99247r1_rule'
  tag stig_id: 'VROM-SL-000765'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-95339r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
