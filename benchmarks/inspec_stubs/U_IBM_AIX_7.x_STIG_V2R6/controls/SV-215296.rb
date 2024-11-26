control 'SV-215296' do
  title 'The AIX SSH daemon must not allow compression.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', %q(Check the SSH daemon configuration for the Compression setting by running: 
# grep -i Compression /etc/ssh/sshd_config | grep -v '^#' 
Compression no

If the setting is not present, or it is not set to "no", this is a finding.)
  desc 'fix', 'Edit the "/etc/ssh/sshd_config" file and add (or modify) the following line:
Compression no

Restart the SSH daemon:
# stopsrc -s sshd
# startsrc -s sshd'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16494r294339_chk'
  tag severity: 'medium'
  tag gid: 'V-215296'
  tag rid: 'SV-215296r508663_rule'
  tag stig_id: 'AIX7-00-002113'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16492r294340_fix'
  tag 'documentable'
  tag legacy: ['SV-101803', 'V-91705']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
