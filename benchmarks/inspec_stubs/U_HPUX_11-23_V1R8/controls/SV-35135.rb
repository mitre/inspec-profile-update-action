control 'SV-35135' do
  title 'The SSH daemon must limit connections to a single session.'
  desc 'The SSH protocol has the ability to provide multiple sessions over a single connection without reauthentication.  A compromised client could use this feature to establish additional sessions to a system without consent or knowledge of the user.

Alternate per-connection session limits may be documented if needed for a valid mission requirement.  Greater limits are expected to be necessary in situations where TCP or X11 forwarding are used.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=MaxSessions
arg(s)=1

Default values include: "10"

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "MaxSessions"

If configuration information is not returned or the return value is greater than one (1), this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the MaxSessions setting value to 1.'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34993r2_chk'
  tag severity: 'low'
  tag gid: 'V-22482'
  tag rid: 'SV-35135r1_rule'
  tag stig_id: 'GEN005533'
  tag gtitle: 'GEN005533'
  tag fix_id: 'F-30287r2_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
