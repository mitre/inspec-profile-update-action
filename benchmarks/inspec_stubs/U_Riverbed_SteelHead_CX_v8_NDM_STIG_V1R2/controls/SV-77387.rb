control 'SV-77387' do
  title 'Riverbed Optimization System (RiOS) must automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever an administrator (or process acting on behalf of a user) accesses a network device. Such administrator sessions can be terminated (and thus terminate network administrator access) without terminating network sessions. 

Session termination terminates all processes associated with an administrator's logical session except those processes that are specifically created by the administrator (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and network device types."
  desc 'check', %q(Verify that RiOS is configured to terminate a network administrator's session after a trigger event such as inactivity timeout.

Navigate to the device CLI
Type: enable
Type: show web
Verify that "Inactivity Timeout:" is set to the organizations defined condition

If no triggers are required by the organization, this is a finding.)
  desc 'fix', %q(Configure RiOS to automatically terminate a network administrator's session after a trigger event such as an inactivity timeout.

Navigate to the device CLI
Type: enable
Type: conf t
Type: web auto-logout <organization defined condition in minutes>
Type: write memory
Type: exit
Type: show web
Verify that "Inactivity Timeout:" represents the value entered above.
Type: exit)
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63663r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62897'
  tag rid: 'SV-77387r1_rule'
  tag stig_id: 'RICX-DM-000039'
  tag gtitle: 'SRG-APP-000295-NDM-000279'
  tag fix_id: 'F-68815r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
