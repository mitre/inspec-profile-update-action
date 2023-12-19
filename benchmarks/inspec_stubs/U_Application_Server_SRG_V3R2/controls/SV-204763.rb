control 'SV-204763' do
  title 'The application server must invalidate session identifiers upon user logout or other session termination.'
  desc 'If communications sessions remain open for extended periods of time even when unused, there is the potential for an adversary to hijack the session and use it to gain access to the device or networks to which it is attached. Terminating sessions after a logout event or after a certain period of inactivity is a method for mitigating the risk of this vulnerability. When a user management session becomes idle, or when a user logs out of the management interface, the application server must terminate the session.'
  desc 'check', 'Review the application server configuration and organizational policy to determine if the system is configured to terminate administrator sessions upon administrator logout or any other organization- or policy-defined session termination events, such as idle time limit exceeded.

If the configuration is not set to terminate administrator sessions per defined events, this is a finding.'
  desc 'fix', 'Configure the application server to terminate administrative sessions upon logout or any other organization- or policy-defined session termination events.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4883r282936_chk'
  tag severity: 'medium'
  tag gid: 'V-204763'
  tag rid: 'SV-204763r508029_rule'
  tag stig_id: 'SRG-APP-000220-AS-000148'
  tag gtitle: 'SRG-APP-000220'
  tag fix_id: 'F-4883r282937_fix'
  tag 'documentable'
  tag legacy: ['V-35415', 'SV-46702']
  tag cci: ['CCI-001185']
  tag nist: ['SC-23 (1)']
end
