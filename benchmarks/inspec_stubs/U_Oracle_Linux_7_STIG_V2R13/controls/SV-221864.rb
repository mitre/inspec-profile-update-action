control 'SV-221864' do
  title 'The Oracle Linux operating system must be configured so that the SSH daemon does not allow compression or only allows compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'Note: For Oracle Linux 7.4 and above, this requirement is not applicable.

Verify the SSH daemon performs compression after a user successfully authenticates.

Check that the SSH daemon performs compression after a user successfully authenticates with the following command:

     # grep -i compression /etc/ssh/sshd_config
     Compression delayed

If the "Compression" keyword is set to "yes", is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "Compression" keyword in "/etc/ssh/sshd_config" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) on the system and set the value to "delayed" or "no":

     Compression no

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23579r880589_chk'
  tag severity: 'medium'
  tag gid: 'V-221864'
  tag rid: 'SV-221864r880591_rule'
  tag stig_id: 'OL07-00-040470'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-23568r880590_fix'
  tag 'documentable'
  tag legacy: ['V-99467', 'SV-108571']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
