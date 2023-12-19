control 'SV-218106' do
  title 'The noexec option must be added to the /tmp partition.'
  desc 'Allowing users to execute binaries from world-writable directories such as "/tmp" should never be necessary in normal operation and can expose the system to potential compromise.'
  desc 'check', %q(To verify that binaries cannot be directly executed from the /tmp directory, run the following command:

$ grep '\s/tmp' /etc/fstab

The resulting output will show whether the /tmp partition has the "noexec" flag set. If the /tmp partition does not have the noexec flag set, this is a finding.)
  desc 'fix', 'The "noexec" mount option can be used to prevent binaries from being executed out of "/tmp". Add the "noexec" option to the fourth column of "/etc/fstab" for the line which controls mounting of "/tmp".'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19587r377333_chk'
  tag severity: 'medium'
  tag gid: 'V-218106'
  tag rid: 'SV-218106r603264_rule'
  tag stig_id: 'RHEL-06-000528'
  tag gtitle: 'SRG-OS-000095'
  tag fix_id: 'F-19585r377334_fix'
  tag 'documentable'
  tag legacy: ['SV-71919', 'V-57569']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
