control 'SV-217917' do
  title 'The system must log Martian packets.'
  desc 'The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.'
  desc 'check', 'The status of the "net.ipv4.conf.all.log_martians" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.log_martians
net.ipv4.conf.all.log_martians = 1

$ grep net.ipv4.conf.all.log_martians /etc/sysctl.conf /etc/sysctl.d/*
net.ipv4.conf.all.log_martians = 1


If "net.ipv4.conf.all.log_martians" is not configured in the /etc/sysctl.conf file or in the /etc/sysctl.d/ directory, is commented out or does not have a value of "1", this is a finding.'
  desc 'fix', 'To set the runtime status of the "net.ipv4.conf.all.log_martians" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.log_martians=1

Set the system to the required kernel parameter by adding the following line to "/etc/sysctl.conf" or a config file in the /etc/sysctl.d/ directory (or modify the line to have the required value): 

net.ipv4.conf.all.log_martians = 1  

 Issue the following command to make the changes take effect:

# sysctl --system'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19398r376766_chk'
  tag severity: 'low'
  tag gid: 'V-217917'
  tag rid: 'SV-217917r603264_rule'
  tag stig_id: 'RHEL-06-000088'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-19396r376767_fix'
  tag 'documentable'
  tag legacy: ['V-38528', 'SV-50329']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
