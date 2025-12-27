control 'SV-35066' do
  title 'The SSH daemon must not permit GSSAPI authentication unless needed.'
  desc 'GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system’s GSSAPI to remote hosts, increasing the attack surface of the system.  GSSAPI authentication must be disabled unless needed.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=GSSAPIAuthentication
arg(s)=no

Default values include: "no"

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "GSSAPIAuthentication"

If the return value is yes, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and delete the keyword entry or modify the entry as follows:

GSSAPIAuthentication no'
  impact 0.3
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-34932r1_chk'
  tag severity: 'low'
  tag gid: 'V-22473'
  tag rid: 'SV-35066r1_rule'
  tag stig_id: 'GEN005524'
  tag gtitle: 'GEN005524'
  tag fix_id: 'F-30238r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
