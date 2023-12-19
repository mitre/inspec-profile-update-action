control 'SV-217996' do
  title 'The SSH daemon must set a timeout interval on idle sessions.'
  desc 'Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.'
  desc 'check', 'Run the following command to see what the timeout interval is: 

# grep ClientAliveInterval /etc/ssh/sshd_config

ClientAliveInterval 600

If "ClientAliveInterval" has a value greater than "600", this is a finding.'
  desc 'fix', 'SSH allows administrators to set an idle timeout interval. After this interval has passed, the idle user will be automatically logged out. 

To set an idle timeout interval, edit the following line in "/etc/ssh/sshd_config" as follows: 

ClientAliveInterval [interval]

The timeout [interval] is given in seconds. To have a timeout of ten minutes, set [interval] to 600. 

If a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made here. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle.'
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19477r603817_chk'
  tag severity: 'low'
  tag gid: 'V-217996'
  tag rid: 'SV-217996r603819_rule'
  tag stig_id: 'RHEL-06-000230'
  tag gtitle: 'SRG-OS-000163'
  tag fix_id: 'F-19475r603818_fix'
  tag 'documentable'
  tag legacy: ['V-38608', 'SV-50409']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
