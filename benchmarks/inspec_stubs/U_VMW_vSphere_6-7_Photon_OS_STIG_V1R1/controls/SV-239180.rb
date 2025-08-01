control 'SV-239180' do
  title 'The Photon operating system must log IPv4 packets with impossible addresses.'
  desc 'The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.'
  desc 'check', 'At the command line, execute the following command:

# /sbin/sysctl -a --pattern "net.ipv4.conf.(all|default|eth.*).log_martians"

Expected result:

net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.eth0.log_martians = 1

If the output does not match the expected result, this is a finding.

Note: The number of "ethx" lines returned is dependent on the number of interfaces. Every "ethx" entry must be set to "1".'
  desc 'fix', 'At the command line, execute the following command:

# for SETTING in $(/sbin/sysctl -aN --pattern "net.ipv4.conf.(all|default|eth.*).log_martians"); do sed -i -e "/^${SETTING}/d" /etc/sysctl.conf;echo $SETTING=1>>/etc/sysctl.conf; done'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42391r675346_chk'
  tag severity: 'medium'
  tag gid: 'V-239180'
  tag rid: 'SV-239180r675348_rule'
  tag stig_id: 'PHTN-67-000109'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-42350r675347_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
