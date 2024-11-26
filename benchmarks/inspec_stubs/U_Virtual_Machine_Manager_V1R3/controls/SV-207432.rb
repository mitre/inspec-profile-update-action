control 'SV-207432' do
  title 'The VMM must automatically terminate a user session after inactivity timeouts have expired or at shutdown.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses a VMM. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated."
  desc 'check', 'Verify the VMM automatically terminates a user session after inactivity timeouts have expired or at shutdown.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to automatically terminate a user session after inactivity timeouts have expired or at shutdown.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7689r365706_chk'
  tag severity: 'medium'
  tag gid: 'V-207432'
  tag rid: 'SV-207432r854607_rule'
  tag stig_id: 'SRG-OS-000279-VMM-001010'
  tag gtitle: 'SRG-OS-000279'
  tag fix_id: 'F-7689r365707_fix'
  tag 'documentable'
  tag legacy: ['V-57065', 'SV-71325']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
