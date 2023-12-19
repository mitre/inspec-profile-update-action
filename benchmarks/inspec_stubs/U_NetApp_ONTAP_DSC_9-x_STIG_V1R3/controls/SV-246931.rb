control 'SV-246931' do
  title 'ONTAP must be configured to enforce the limit of three consecutive failed logon attempts.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Use the command "security login role config show" to get a list of roles.

For each role, use the command "security login role config show -vserver <vserver_name> -role <role_name>" to view the password requirements for each role. 

If any role has "Maximum Number of Failed Attempts" not set to "3", this is a finding.

Use "security login role config show -role admin -instance" to see the settings for "Maximum Number of Failed Attempts" and “Lockout Duration".

Note: Lockout duration is set by default to lockout for one day or until unlocked by an administrator. It cannot be set to less than one day.

If ONTAP is not configured to enforce a limit of three consecutive invalid logon attempts, this is a finding.'
  desc 'fix', 'Use the command "security login role config show" to get a list of roles.

For each role, use the command "security login role config show -vserver <vserver_name> -role <role_name>" to view the password requirements for each role. 

For any role that does not have "Maximum Number of Failed Attempts" set to "3", use the command "security login role config modify -role <role_name> -vserver <vserver_name>  -max-failed-login-attempts 3".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50363r877994_chk'
  tag severity: 'medium'
  tag gid: 'V-246931'
  tag rid: 'SV-246931r877996_rule'
  tag stig_id: 'NAOT-AC-000010'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-50317r877995_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
