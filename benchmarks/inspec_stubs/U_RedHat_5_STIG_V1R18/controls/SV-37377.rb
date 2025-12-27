control 'SV-37377' do
  title 'The root account must not be used for direct log in.'
  desc 'Direct login with the root account prevents individual user accountability.  Acceptable non-routine uses of the root account for direct login are limited to emergency maintenance, the use of single-user mode for maintenance, and situations where individual administrator accounts are not available.'
  desc 'check', 'Check if root is used for direct logins.

Procedure:
# last root | grep -v reboot

Direct logins are indicated by the presence of a terminal or pseudo-terminal ID and/or X display name in the output of the last command.  If any direct login records for root are listed, this is a finding.'
  desc 'fix', 'Enforce policy requiring all root account access is attained by first logging into a user account and then becoming root preferably through the use of "sudo" which provides traceability to the command level. If that is not workable then using "su" to access the root account will provide traceability to the login user.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36064r5_chk'
  tag severity: 'medium'
  tag gid: 'V-11979'
  tag rid: 'SV-37377r2_rule'
  tag stig_id: 'GEN001020'
  tag gtitle: 'GEN001020'
  tag fix_id: 'F-31308r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
