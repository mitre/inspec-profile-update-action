control 'SV-250603' do
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# grep Compression /etc/ssh/sshd_config

If the command returns nothing, or if the "Compression" attribute is set to "yes", this is a finding.

Re-enable lock down mode.'
  desc 'fix', 'Disable lock down mode. Enable the ESXi Shell. Execute the following command(s):
# vi /etc/ssh/sshd_config

Add/modify the attribute line entry to the following (quotes for emphasis only):
"Compression no" 
or 
"Compression delayed"

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54038r798806_chk'
  tag severity: 'medium'
  tag gid: 'V-250603'
  tag rid: 'SV-250603r798808_rule'
  tag stig_id: 'GEN005539-ESXI5-000113'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53992r798807_fix'
  tag 'documentable'
  tag legacy: ['V-39285', 'SV-51101']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
