control 'SV-252943' do
  title 'The TOSS SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'Verify the SSH daemon performs compression after a user successfully authenticates with the following command:

$ sudo grep -i compression /etc/ssh/sshd_config

Compression delayed

If the "Compression" keyword is set to "yes", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "Compression" keyword in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) on the system and set the value to "delayed" or "no":

Compression no

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56396r824151_chk'
  tag severity: 'medium'
  tag gid: 'V-252943'
  tag rid: 'SV-252943r824153_rule'
  tag stig_id: 'TOSS-04-010410'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56346r824152_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
