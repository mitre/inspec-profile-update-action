control 'SV-25054' do
  title 'OS accounts used to execute external procedures should be assigned minimum privileges.'
  desc 'External applications spawned by the DBMS process may be executed under OS accounts assigned unnecessary privileges that can lead to unauthorized access to OS resources. Unauthorized access to OS resources can lead to the compromise of the OS, the DBMS, and any other service provided by the host platform.'
  desc 'check', 'Determine which OS accounts external DBMS executables are run.

Review the privileges assigned to these accounts and compare them to the System Security Plan and the function of the applications.

If assigned privileges exceed those necessary to operate as designed or the privileges do not match the list of required privileges for the application in the System Security Plan, this is a Finding.'
  desc 'fix', 'Configure OS accounts used by DBMS external procedures to have the minimum privileges necessary for operation.

Document DBMS external procedures and OS privileges need to execute the procedures in the System Security Plan.'
  impact 0.5
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-1769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15620'
  tag rid: 'SV-25054r1_rule'
  tag stig_id: 'DG0101-ORACLE11'
  tag gtitle: 'DBMS external procedure OS account privileges'
  tag fix_id: 'F-3795r1_fix'
  tag 'documentable'
  tag responsibility: 'Database Administrator'
end
