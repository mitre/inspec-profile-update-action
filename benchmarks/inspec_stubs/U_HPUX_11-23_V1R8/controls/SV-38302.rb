control 'SV-38302' do
  title 'The system must display the date and time of the last successful account login upon login.'
  desc 'Providing users with feedback on when account accesses last occurred facilitates user recognition and reporting of unauthorized account use.'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=PrintLastLog
Required arg(s)=yes

Default arg values include: "yes"

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> are not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "PrintLastLog" | cut -f 2,2 -d " "

If the return value is no, this is a finding.)
  desc 'fix', 'Edit the configuration file and modify the PrintLastLog line entry as follows:

PrintLastLog yes'
  impact 0.3
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36261r1_chk'
  tag severity: 'low'
  tag gid: 'V-22299'
  tag rid: 'SV-38302r1_rule'
  tag stig_id: 'GEN000452'
  tag gtitle: 'GEN000452'
  tag fix_id: 'F-31518r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000052']
  tag nist: ['AC-9']
end
