control 'SV-235180' do
  title 'Execution of software modules (to include stored procedures, functions, and triggers) with elevated privileges must be restricted to necessary cases only.'
  desc 'In certain situations, to provide required functionality, a Database Management System (DBMS) needs to execute internal logic (stored procedures, functions, triggers, etc.) and/or external code modules with elevated privileges. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking the functionality applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.

Privilege elevation must be utilized only where necessary and protected from misuse.'
  desc 'check', "Review the server documentation to obtain a listing of accounts used for executing external processes. Execute the following query to obtain a listing of accounts currently configured for use by external processes. 

SHOW PROCEDURE STATUS where security_type <> 'INVOKER';
SHOW FUNCTION STATUS where security_type <> 'INVOKER';

If DEFINER accounts are returned that are not documented and authorized, this is a finding.

If elevation of MySQL privileges using DEFINER is documented, but not implemented as described in the documentation, this is a finding.

If the privilege-elevation logic can be invoked in ways other than intended, or in contexts other than intended, or by subjects/principals other than intended, this is a finding."
  desc 'fix', 'Remove any procedures that are not authorized.

Drop the procedure or function using 
DROP PROCEDURE <proc_name>;
DROP FUNCTION <function_name>;'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38399r623660_chk'
  tag severity: 'medium'
  tag gid: 'V-235180'
  tag rid: 'SV-235180r638812_rule'
  tag stig_id: 'MYS8-00-010600'
  tag gtitle: 'SRG-APP-000342-DB-000302'
  tag fix_id: 'F-38362r623661_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
