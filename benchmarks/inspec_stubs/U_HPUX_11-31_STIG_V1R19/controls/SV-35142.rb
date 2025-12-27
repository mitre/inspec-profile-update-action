control 'SV-35142' do
  title 'The SSH daemon must not allow rhosts RSA authentication.'
  desc 'If SSH permits rhosts RSA authentication, a user may be able to login based on the keys of the host originating the request and not any user-specific authentication..'
  desc 'check', %q(Check the SSH daemon configuration. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=RhostsRSAAuthentication
arg(s)=no

Default values include: "no"

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "RhostsRSAAuthentication"

This option currently applies only to Protocol Version 1. If using Protocol 1 or any variant of Protocol 1, IE:

Protocol 1,2

OR

Protocol 2,1

and configuration information is not returned or the return value is yes, this is a finding. If using Protocol 2, this is Not Applicable (NA).)
  desc 'fix', 'Edit the SSH daemon configuration and add or edit the RhostsRSAAuthentication setting value to no.   

Note that the above guidance applies exclusively to Protocol(s) 1/1,2/2,1 only. If using Protocol 2 only, the check is not applicable and further action is not required.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-35000r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22487'
  tag rid: 'SV-35142r1_rule'
  tag stig_id: 'GEN005538'
  tag gtitle: 'GEN005538'
  tag fix_id: 'F-30293r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
