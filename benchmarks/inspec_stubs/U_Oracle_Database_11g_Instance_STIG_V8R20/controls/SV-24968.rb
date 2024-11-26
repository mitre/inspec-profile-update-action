control 'SV-24968' do
  title 'DBMS passwords should not be stored in compiled, encoded or encrypted batch jobs or compiled, encoded or encrypted application source code.'
  desc 'The storage of passwords in application source or batch job code that is compiled, encoded or encrypted prevents compliance with password expiration and other management requirements as well as provides another means for potential discovery.'
  desc 'check', 'Ask the DBA to review application source code that is required by Check DG0091 to be encoded or encrypted for database accounts used by applications or batch jobs to access the database.

Ask the DBA to review source batch job code prior to compiling, encoding or encrypting for database accounts used by applications or the batch jobs themselves to access the database.

Ask the DBA and/or IAO to determine if the compiled, encoded or encrypted application source code or batch jobs contain passwords used for authentication to the database.

If none of the identified compiled, encoded or encrypted application source code or batch job code contain passwords used for authentication, this check is Not a Finding.

If any of the identified compiled, encoded or encrypted application source code or batch job code do contain passwords used for authentication to the database, this is a Finding.

NOTE: This check only applies to application source code or batch job code that is compiled, encoded or encrypted in a production environment. Application source code or batch job code that is not compiled, encoded or encrypted would fall under Check DG0067 for determination of compliance.'
  desc 'fix', 'Design DBMS application code and batch job code that is compiled, encoded or encrypted to NOT contain passwords.

Consider alternatives to using password authentication for compiled, encoded or encrypted batch jobs and DBMS application code.'
  impact 0.5
  ref 'DPMS Target Oracle Databases 11g'
  tag check_id: 'C-24316r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15637'
  tag rid: 'SV-24968r2_rule'
  tag stig_id: 'DG0130-ORACLE11'
  tag gtitle: 'DBMS passwords in batch and applic. source code'
  tag fix_id: 'F-3413r1_fix'
  tag 'documentable'
  tag responsibility: ['Database Administrator', 'Information Assurance Officer']
end
