control 'SV-213586' do
  title 'EDB Postgres Advanced Server software modules, to include stored procedures, functions and triggers must be monitored to discover unauthorized changes.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals must be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.  Monitoring is required for assurance that the protections are effective.

Unmanaged changes that occur to the logic modules within the database can lead to unauthorized or compromised installations.'
  desc 'check', 'Check the EDB Postgres configuration for a timed job that automatically checks all system and user-defined procedures, functions and triggers for being modified by running the following EDB Postgres query: 
select job, what from ALL_JOBS; 

(Alternatively, in Postgres Enterprise Manager, navigate to the "Jobs" node of the database and examine the job from there.) 

If a timed job or some other method is not implemented to check for Triggers being modified, this is a finding.'
  desc 'fix', 'Configure an EDB Postgres timed job that automatically checks all system and user-defined procedures, functions and triggers for being modified, and in the event of such changes informs the proper personnel for evaluation and possible action.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14808r290070_chk'
  tag severity: 'medium'
  tag gid: 'V-213586'
  tag rid: 'SV-213586r508024_rule'
  tag stig_id: 'PPS9-00-003210'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-14806r290071_fix'
  tag 'documentable'
  tag legacy: ['SV-83531', 'V-68927']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
