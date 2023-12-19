control 'SV-35137' do
  title 'The SSH daemon must perform strict mode checking of home directory configuration files.'
  desc 'If other users have access to modify user-specific SSH configuration files, they may be able to log into the system as another user.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=StrictModes
arg(s)=yes

Default values include: "yes"

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "StrictModes"

If the return value is no, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the StrictModes setting value to yes.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34995r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22485'
  tag rid: 'SV-35137r1_rule'
  tag stig_id: 'GEN005536'
  tag gtitle: 'GEN005536'
  tag fix_id: 'F-30289r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
