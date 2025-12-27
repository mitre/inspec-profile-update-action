control 'SV-35214' do
  title 'The SSH daemon must only listen on management network addresses unless authorized for uses other than management.'
  desc 'The SSH daemon should only listen on network addresses designated for management traffic. If the system has multiple network interfaces and SSH listens on addresses not designated for management traffic, the SSH service could be subject to unauthorized access. If SSH is used for purposes other than management, such as providing an SFTP service, the list of approved listening addresses may be documented.'
  desc 'check', %q(Ask the SA if any/all interfaces are authorized for management traffic. If all interfaces are authorized, this is not a finding.

Check the SSH daemon configuration for listening network addresses. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=ListenAddress
arg(s)=<site specific>

Default arg values include: NA. The default action is for the daemon to listen on all local addresses. In this case, the ListenAddress line entry will not be found in the configuration file.

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> are not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | grep -v '^#' | grep -i "ListenAddress"

If a returned 'ListenAddress' configuration entry contains addresses not designated for management traffic, this is a finding.)
  desc 'fix', 'Edit the configuration file to specify listening for network addresses designated for management traffic only, or remove the ListenAddress line entry.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36632r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22457'
  tag rid: 'SV-35214r1_rule'
  tag stig_id: 'GEN005504'
  tag gtitle: 'GEN005504'
  tag fix_id: 'F-32001r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000069']
  tag nist: ['AC-17 (3)']
end
