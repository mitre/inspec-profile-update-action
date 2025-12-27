control 'SV-251635' do
  title 'CA IDMS CV must supply logout functionality to allow the user to implicitly terminate a batch external request unit when the batch job abnormally terminates.'
  desc 'IDMS must provide a facility by which an inactive user session may be terminated after a predetermined period of time.'
  desc 'check', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example. 

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.

Scroll through the returned text until "CHKUSER TASK" is found.

If the associated value is not the organization-defined number of subtasks that detect abnormally terminated batch external request units, this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 CHKUSER TASK is <the organization-defined number of subtasks> ." where 123 is the number of the system being modified.

Enter: "GENERATE."

The change will become effective the next time the CV is stopped and started.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55070r807770_chk'
  tag severity: 'medium'
  tag gid: 'V-251635'
  tag rid: 'SV-251635r855273_rule'
  tag stig_id: 'IDMS-DB-000640'
  tag gtitle: 'SRG-APP-000296-DB-000306'
  tag fix_id: 'F-55024r807771_fix'
  tag 'documentable'
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
