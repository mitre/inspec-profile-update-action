control 'SV-251629' do
  title 'CA IDMS must automatically terminate a batch external request unit after organization-defined conditions or trigger events after the batch program abnormally terminates.'
  desc "A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions. 

Session termination ends all processes associated with a user's logical session except those batch processes/jobs that are specifically created by the user (i.e., session owner) to continue after the session is terminated. 

Conditions or trigger events requiring automatic session termination can include, for example, organization-defined periods of user inactivity, targeted responses to certain types of incidents, and time-of-day restrictions on information system use.

This capability is typically reserved for specific cases where the system owner, data owner, or organization requires additional assurance.

If a batch request terminates abnormally the external run unit process needs to be terminated."
  desc 'check', 'Use task SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example. 

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.

Scroll through the returned text until "CHKUSER TASK" is found.

If the associated value is not the organization-defined number of subtasks that detect abnormally terminated batch external request units, this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 CHKUSER TASK is <the organization-defined number of subtasks> ." where 123 is the number of the system being modified.

Enter: "VALIDATE."

Enter: "GENERATE."

The change will become effective the next time the CV is stopped and started.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55064r807752_chk'
  tag severity: 'medium'
  tag gid: 'V-251629'
  tag rid: 'SV-251629r855267_rule'
  tag stig_id: 'IDMS-DB-000580'
  tag gtitle: 'SRG-APP-000295-DB-000305'
  tag fix_id: 'F-55018r807753_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
