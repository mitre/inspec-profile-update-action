control 'SV-217286' do
  title 'The SUSE operating system must be configured to use TCP syncookies.'
  desc 'Denial of Service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 

Managing excess capacity ensures that sufficient capacity is available to counter flooding attacks. Employing increased capacity and service redundancy may reduce the susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning.'
  desc 'check', 'Verify the SUSE operating system is configured to use TCP syncookies.

Check to see if syncookies are used with the following command:

# sudo sysctl net.ipv4.tcp_syncookies

net.ipv4.tcp_syncookies = 1

If the value is not set to "1", this is a finding.'
  desc 'fix', %q(Configure the SUSE operating system to use TCP syncookies by running the following command as an administrator:

# sudo sysctl -w net.ipv4.tcp_syncookies=1

If "1" is not the system's default value, add or update the following line in "/etc/sysctl.conf":

net.ipv4.tcp_syncookies = 1)
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18514r370014_chk'
  tag severity: 'medium'
  tag gid: 'V-217286'
  tag rid: 'SV-217286r603262_rule'
  tag stig_id: 'SLES-12-030350'
  tag gtitle: 'SRG-OS-000142-GPOS-00071'
  tag fix_id: 'F-18512r370015_fix'
  tag 'documentable'
  tag legacy: ['V-77485', 'SV-92181']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
