control 'SV-248604' do
  title 'The OL 8 SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'Verify the SSH daemon performs compression after a user successfully authenticates with the following command: 
 
$ sudo grep -i compression /etc/ssh/sshd_config 
 
Compression delayed 
 
If the "Compression" keyword is set to "yes" or is missing, or if the returned line is commented out, this is a finding.'
  desc 'fix', 'Uncomment the "Compression" keyword in "/etc/ssh/sshd_config" on the system (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to "delayed" or "no": 
 
Compression no 
 
The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52038r779376_chk'
  tag severity: 'medium'
  tag gid: 'V-248604'
  tag rid: 'SV-248604r779378_rule'
  tag stig_id: 'OL08-00-010510'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51992r779377_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
