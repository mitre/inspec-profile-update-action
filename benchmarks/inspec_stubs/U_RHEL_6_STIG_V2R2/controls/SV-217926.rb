control 'SV-217926' do
  title 'The system must ignore ICMPv6 redirects by default.'
  desc 'An illicit ICMP redirect message could result in a man-in-the-middle attack.'
  desc 'check', 'If IPv6 is disabled, this is not applicable.

The status of the "net.ipv6.conf.default.accept_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv6.conf.default.accept_redirects
net.ipv6.conf.default.accept_redirects = 0

$ grep net.ipv6.conf.default.accept_redirects /etc/sysctl.conf /etc/sysctl.d/*
net.ipv6.conf.default.accept_redirects = 0

If "net.ipv6.conf.default.accept_redirects" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of "0", this is a finding.'
  desc 'fix', 'To set the runtime status of the "net.ipv6.conf.default.accept_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv6.conf.default.accept_redirects=0

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value):  

net.ipv6.conf.default.accept_redirects = 0

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19407r376793_chk'
  tag severity: 'medium'
  tag gid: 'V-217926'
  tag rid: 'SV-217926r603264_rule'
  tag stig_id: 'RHEL-06-000099'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19405r376794_fix'
  tag 'documentable'
  tag legacy: ['V-38548', 'SV-50349']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
