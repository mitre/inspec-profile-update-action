control 'SV-217919' do
  title 'The system must not accept ICMPv4 secure redirect packets by default.'
  desc 'Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required.'
  desc 'check', 'The status of the "net.ipv4.conf.default.secure_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.secure_redirects
net.ipv4.conf.default.secure_redirects = 0

$ grep net.ipv4.conf.default.secure_redirects /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.conf.default.secure_redirects = 0

If "net.ipv4.conf.default.secure_redirect" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of "0", this is a finding.'
  desc 'fix', 'To set the runtime status of the "net.ipv4.conf.default.secure_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.secure_redirects=0

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value): 

net.ipv4.conf.default.secure_redirects = 0

Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19400r376772_chk'
  tag severity: 'medium'
  tag gid: 'V-217919'
  tag rid: 'SV-217919r603264_rule'
  tag stig_id: 'RHEL-06-000090'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19398r376773_fix'
  tag 'documentable'
  tag legacy: ['V-38532', 'SV-50333']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
