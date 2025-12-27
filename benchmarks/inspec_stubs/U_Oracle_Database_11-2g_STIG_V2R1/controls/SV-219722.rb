control 'SV-219722' do
  title 'The Oracle _TRACE_FILES_PUBLIC parameter if present must be set to FALSE.'
  desc 'The _TRACE_FILES_PUBLIC parameter is used to make trace files used for debugging database applications and events available to all database users. Use of this capability precludes the discrete assignment of privileges based on job function. Additionally, its use may provide access to external files and data to unauthorized users.'
  desc 'check', "From SQL*Plus:

select value from v$parameter where name = '_trace_files_public';

If the value returned is TRUE, this is a Finding.

If the parameter does not exist or is set to FALSE, this is Not a Finding."
  desc 'fix', "From SQL*Plus (shutdown database instance):

shutdown immediate

From SQL*Plus (create a pfile from spfile):

create pfile='[PATH]init[SID].ora' from spfile;

Edit the init[SID].ora file and remove the following line:

*._trace_files_public=TRUE

From SQL*Plus (update the spfile using the pfile):

create spfile from pfile='[PATH]init[SID].ora';

From SQL*Plus (start the database instance):

startup

NOTE: [PATH] depends on the platform (Windows or UNIX).

Ensure the file is directed to a writable location.

[SID] is equal to the oracle SID or database instance ID."
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-21447r307015_chk'
  tag severity: 'medium'
  tag gid: 'V-219722'
  tag rid: 'SV-219722r401224_rule'
  tag stig_id: 'O112-BP-023900'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-21446r307016_fix'
  tag 'documentable'
  tag legacy: ['SV-68255', 'V-54015']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
