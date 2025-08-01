control 'SV-235012' do
  title 'The SUSE operating system SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'Verify the SUSE operating system SSH daemon performs compression after a user successfully authenticates.

Check that the SSH daemon performs compression after a user successfully authenticates with the following command:

> sudo grep -i compression /etc/ssh/sshd_config
Compression delayed

If the "Compression" keyword is set to "yes", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system SSH daemon performs compression after a user successfully authenticates.

Uncomment the "Compression" keyword in "/etc/ssh/sshd_config" on the system and set the value to "delayed" or "no":

Compression no'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38200r619305_chk'
  tag severity: 'medium'
  tag gid: 'V-235012'
  tag rid: 'SV-235012r622137_rule'
  tag stig_id: 'SLES-15-040280'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38163r619306_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
