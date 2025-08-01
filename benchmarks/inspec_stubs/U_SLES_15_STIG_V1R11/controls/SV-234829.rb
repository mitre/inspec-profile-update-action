control 'SV-234829' do
  title 'The SUSE operating system must be configured to use TCP syncookies.'
  desc 'Denial of Service (DoS) is a condition in which a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify the SUSE operating system is configured to use IPv4 TCP syncookies.

Check to see if syncookies are used with the following command:

> sudo sysctl net.ipv4.tcp_syncookies
net.ipv4.tcp_syncookies = 1

If the network parameter "ipv4.tcp_syncookies" is not equal to "1" or nothing is returned, this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to use IPv4 TCP syncookies by running the following command as an administrator:

> sudo sysctl -w net.ipv4.tcp_syncookies=1

If "1" is not the system's default value, add or update the following line in "/etc/sysctl.d/99-stig.conf":

> sudo sh -c 'echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/99-stig.conf'

> sudo sysctl --system)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38017r618756_chk'
  tag severity: 'medium'
  tag gid: 'V-234829'
  tag rid: 'SV-234829r622137_rule'
  tag stig_id: 'SLES-15-010310'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-37980r618757_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
