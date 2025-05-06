control 'SV-252186' do
  title 'The HPE Nimble must initiate a session lock after a 15-minute period of inactivity.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device. Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock. Once invoked, the session lock must remain in place until the administrator reauthenticates. No other system activity aside from reauthentication must unlock the management session.

Note that CCI-001133 requires that administrative network sessions be disconnected after 10 minutes of idle time. So this requirement may only apply to local administrative sessions.'
  desc 'check', 'Type "group --info | grep inactivity" and review the timeout value. If it is greater than 15 minutes, this is a finding.'
  desc 'fix', 'Type "group --edit --inactivity_timeout 15".'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55642r814036_chk'
  tag severity: 'medium'
  tag gid: 'V-252186'
  tag rid: 'SV-252186r814038_rule'
  tag stig_id: 'HPEN-NM-000010'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag fix_id: 'F-55592r814037_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
