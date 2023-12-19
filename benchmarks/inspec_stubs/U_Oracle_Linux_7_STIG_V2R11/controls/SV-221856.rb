control 'SV-221856' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol.'
  desc 'SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.

'
  desc 'check', 'Check the version of the operating system with the following command:

# cat /etc/oracle-release

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
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23571r419640_chk'
  tag severity: 'high'
  tag gid: 'V-221856'
  tag rid: 'SV-221856r877396_rule'
  tag stig_id: 'OL07-00-040390'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag fix_id: 'F-23560r419641_fix'
  tag satisfies: ['SRG-OS-000074-GPOS-00042', 'SRG-OS-000480-GPOS-00227']
  tag 'documentable'
  tag legacy: ['SV-108555', 'V-99451']
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
