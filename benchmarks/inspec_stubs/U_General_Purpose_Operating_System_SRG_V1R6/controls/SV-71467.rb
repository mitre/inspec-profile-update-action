control 'SV-71467' do
  title 'The operating system must automatically terminate a user session after inactivity time-outs have expired or at shutdown.'
  desc "Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.

Session termination terminates all processes associated with a user's logical session except those processes that are specifically created by the user (i.e., session owner) to continue after the session is terminated.

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific operating system functionality where the system owner, data owner, or organization requires additional assurance."
  desc 'check', 'Verify the operating system automatically terminates a user session after inactivity time-outs have expired or at shutdown. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to automatically terminate a user session after inactivity time-outs have expired or at shutdown.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57207'
  tag rid: 'SV-71467r1_rule'
  tag stig_id: 'SRG-OS-000279-GPOS-00109'
  tag gtitle: 'SRG-OS-000279-GPOS-00109'
  tag fix_id: 'F-62119r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
