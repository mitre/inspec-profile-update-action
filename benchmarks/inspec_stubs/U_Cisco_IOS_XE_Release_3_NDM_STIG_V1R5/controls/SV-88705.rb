control 'SV-88705' do
  title 'The Cisco IOS XE router must automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever an administrator (or process acting on behalf of a user) accesses a network device. Such administrator sessions can be terminated (and thus terminate network administrator access) without terminating network sessions. 

Session termination terminates all processes associated with an administrator's logical session except those processes that are specifically created by the administrator (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and network device types."
  desc 'check', 'Verify that the Cisco IOS XE router is configured to automatically terminate sessions.

The configuration should look similar to the example below:
 
line vty 0 5
 exec-timeout 10 0

If sessions do not automatically terminate, this is a finding.'
  desc 'fix', 'Configure session time outs and idle time outs on all management interfaces using the following commands:        
 
line vty 0 5
 exec-timeout 10 0'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74121r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74031'
  tag rid: 'SV-88705r2_rule'
  tag stig_id: 'CISR-ND-000083'
  tag gtitle: 'SRG-APP-000295-NDM-000279'
  tag fix_id: 'F-80573r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
