control 'SV-207622' do
  title 'The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'From an SSH session connected to the ESXi host, or from the ESXi shell, run the following command:

# grep -i "^Compression" /etc/ssh/sshd_config

If there is no output or the output is not exactly "Compression no", this is a finding.'
  desc 'fix', 'From an SSH session connected to the ESXi host, or from the ESXi shell, add or correct the following line in "/etc/ssh/sshd_config":

Compression no'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7877r364265_chk'
  tag severity: 'medium'
  tag gid: 'V-207622'
  tag rid: 'SV-207622r388482_rule'
  tag stig_id: 'ESXI-65-000021'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7877r364266_fix'
  tag 'documentable'
  tag legacy: ['SV-104075', 'V-93989']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
