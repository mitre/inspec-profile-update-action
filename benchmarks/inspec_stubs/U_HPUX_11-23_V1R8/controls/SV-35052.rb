control 'SV-35052' do
  title 'The SSH daemon must restrict login ability to specific users and/or groups.'
  desc 'Restricting SSH logins to a limited group of users, such as system administrators, prevents password guessing and other SSH attacks from reaching system accounts and other accounts not authorized for SSH access.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword(s)=DenyUsers, AllowUsers, DenyGroups, AllowGroups (order of precedence, most to least).
arg(s)=<site specific>

Default values for users/groups include: "<valid, space-separated user and/or group names. UID's/GIDs are not allowed/valid>". Lack of keyword(s) in the configuration file will result in allowing ssh access to all users and all groups. A typical installation should either include an allow (users/groups) list or deny (users/groups) list depending on what the defined site security requirements are.

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | egrep -i "DenyUsers|AllowUsers|DenyGroups|AllowGroups"

If keyword(s) with valid, space-separated user(s) and/or group(s) are not returned, this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and add the appropriate keyword directive(s) and space-separated user/group names. The keyword order of precedence is as follows:

DenyUsers, AllowUsers, DenyGroups, AllowGroups'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-34923r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22470'
  tag rid: 'SV-35052r1_rule'
  tag stig_id: 'GEN005521'
  tag gtitle: 'GEN005521'
  tag fix_id: 'F-30228r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
