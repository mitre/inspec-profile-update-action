control 'SV-202007' do
  title 'The network device must initiate a session lock after a 15-minute period of inactivity.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device.  Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock.  Once invoked, the session lock shall remain in place until the administrator re-authenticates. No other system activity aside from re-authentication shall unlock the management session.

Note that CCI-001133 requires that administrative network sessions be disconnected after 10 minutes of idle time. So this requirement may only apply to local administrative sessions.'
  desc 'check', 'Review the network device configuration to see if it initiates a session lock after a 15-minute period of inactivity.  This may be verified by configuration check or demonstration. If a session lock is not initiated after a 15-minute period of inactivity, this is a finding.'
  desc 'fix', 'Configure the network device to initiate a session lock after a 15-minute period of inactivity.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2133r381560_chk'
  tag severity: 'medium'
  tag gid: 'V-202007'
  tag rid: 'SV-202007r395448_rule'
  tag stig_id: 'SRG-APP-000003-NDM-000202'
  tag gtitle: 'SRG-APP-000003'
  tag fix_id: 'F-2134r381561_fix'
  tag 'documentable'
  tag legacy: ['SV-69277', 'V-55031']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
