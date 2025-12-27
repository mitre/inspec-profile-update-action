control 'SV-91677' do
  title 'The DBN-6300 must automatically terminate a network administrator session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "Automatic session termination addresses the termination of administrator-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever an administrator (or process acting on behalf of a user) accesses a network device. Such administrator sessions can be terminated (and thus terminate network administrator access) without terminating network sessions. 

Session termination terminates all processes associated with an administrator's logical session except those processes that are specifically created by the administrator (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use. These conditions will vary across environments and network device types."
  desc 'check', 'Verify administrator accounts are configured with a 10 minute timeout setting.

Navigate to Settings >> Users.

Click on the wrench for an existing user.

View each user defined on the device since there is no setting for a global value.

If a timeout value of "600" is not set for each administrator account configured on the device, this is a finding.'
  desc 'fix', 'Configure administrator accounts with a timeout setting.

Navigate to Settings >> Users.

Click on the wrench for an existing user.

In the "Edit User" popup box, enter a timeout value of "600".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76607r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76981'
  tag rid: 'SV-91677r1_rule'
  tag stig_id: 'DBNW-DM-000083'
  tag gtitle: 'SRG-APP-000295-NDM-000279'
  tag fix_id: 'F-83677r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
