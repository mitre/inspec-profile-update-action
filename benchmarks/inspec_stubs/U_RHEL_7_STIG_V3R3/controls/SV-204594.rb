control 'SV-204594' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.

'
  desc 'check', 'Check the version of the operating system with the following command:

# cat /etc/redhat-release

If the release is 7.4 or newer this requirement is Not Applicable.

Verify the SSH daemon is configured to only use the SSHv2 protocol.

Check that the SSH daemon is configured to only use the SSHv2 protocol with the following command:

# grep -i protocol /etc/ssh/sshd_config
Protocol 2
#Protocol 1,2

If any protocol line other than "Protocol 2" is uncommented, this is a finding.'
  desc 'fix', 'Remove all Protocol lines that reference version "1" in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor). The "Protocol" line must be as follows:

Protocol 2

The SSH service must be restarted for changes to take effect.'
  impact 0.7
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4718r88974_chk'
  tag severity: 'high'
  tag gid: 'V-204594'
  tag rid: 'SV-204594r603261_rule'
  tag stig_id: 'RHEL-07-040390'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-4718r88975_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['SV-86875', 'V-72251']
  tag cci: ['CCI-000366', 'CCI-000197']
  tag nist: ['CM-6 b', 'IA-5 (1) (c)']
end
