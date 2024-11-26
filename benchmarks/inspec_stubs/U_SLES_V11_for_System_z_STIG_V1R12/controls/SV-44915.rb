control 'SV-44915' do
  title 'The root account must not be used for direct log in.'
  desc 'Direct login with the root account prevents individual user accountability.  Acceptable non-routine uses of the root account for direct login are limited to emergency maintenance, the use of single-user mode for maintenance, and situations where individual administrator accounts are not available.'
  desc 'check', 'Check if the root is used for direct logins.

Procedure:
# last root | grep -v reboot

If any direct login records for root exist, this is a finding.'
  desc 'fix', 'Enforce policy requiring all root account access is attained by first logging into a user account and then becoming root preferably through the use of "sudo" which provides traceability to the command level. If that is not workable then using "su" to access the root account will provide traceability to the login user.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42356r1_chk'
  tag severity: 'medium'
  tag gid: 'V-11979'
  tag rid: 'SV-44915r1_rule'
  tag stig_id: 'GEN001020'
  tag gtitle: 'GEN001020'
  tag fix_id: 'F-38347r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
