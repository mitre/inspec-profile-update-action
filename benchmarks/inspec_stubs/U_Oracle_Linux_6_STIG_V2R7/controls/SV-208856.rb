control 'SV-208856' do
  title 'The system must log Martian packets.'
  desc 'The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.'
  desc 'check', 'The status of the "net.ipv4.conf.all.log_martians" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.log_martians

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.log_martians /etc/sysctl.conf

If the correct value is not returned, this is a finding.'
  desc 'fix', %q(To set the runtime status of the "net.ipv4.conf.all.log_martians" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.log_martians=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.log_martians = 1)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9109r357548_chk'
  tag severity: 'low'
  tag gid: 'V-208856'
  tag rid: 'SV-208856r793641_rule'
  tag stig_id: 'OL6-00-000088'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9109r357549_fix'
  tag 'documentable'
  tag legacy: ['V-50625', 'SV-64831']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
