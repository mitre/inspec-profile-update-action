control 'SV-206580' do
  title 'The DBMS must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc "This addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance."
  desc 'check', "Review system documentation to obtain the organization's definition of circumstances requiring automatic session termination. If the documentation explicitly states that such termination is not required or is prohibited, this is not a finding.

If the documentation requires automatic session termination, but the DBMS is not configured accordingly, this is a finding."
  desc 'fix', 'Configure the DBMS to automatically terminate a user session after organization-defined conditions or trigger events requiring session termination.'
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6840r291408_chk'
  tag severity: 'medium'
  tag gid: 'V-206580'
  tag rid: 'SV-206580r617447_rule'
  tag stig_id: 'SRG-APP-000295-DB-000305'
  tag gtitle: 'SRG-APP-000295'
  tag fix_id: 'F-6840r291409_fix'
  tag 'documentable'
  tag legacy: ['SV-72455', 'V-58025']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
