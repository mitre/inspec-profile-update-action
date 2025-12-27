control 'SV-35146' do
  title 'The SSH daemon must not allow compression or must only allow compression after successful authentication.'
  desc 'If compression is allowed in an SSH connection prior to authentication, vulnerabilities in the compression software could result in compromise of the system from an unauthenticated connection, potentially with root privileges.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=Compression
arg(s)="no" OR "delayed", IE: mutually exclusive arguments, should never occur together

Default values include: "delayed"

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "Compression"

If configuration information is not returned or the return value is yes, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the Compression setting value to no or delayed.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35004r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22488'
  tag rid: 'SV-35146r1_rule'
  tag stig_id: 'GEN005539'
  tag gtitle: 'GEN005539'
  tag fix_id: 'F-30297r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
