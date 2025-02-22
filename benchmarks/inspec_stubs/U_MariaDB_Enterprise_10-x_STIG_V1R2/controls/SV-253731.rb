control 'SV-253731' do
  title 'MariaDB must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

DBMS functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

The DBMS must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect by the organization). 

In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.'
  desc 'check', "If MariaDB supports only software development, experimentation and/or developer-level testing (that is, excluding production systems, integration testing, stress testing, and user acceptance testing), this is not a finding.

Review MariaDB and database security settings with respect to nonadministrative users ability to create, alter, or replace logic modules, to include but not necessarily only stored procedures, functions, triggers, and views.

1. To list the privileges for all users on all tables and schemas, as the database administrator, run the following:
 
Gather a list of SHOW GRANTS commands. SHOW GRANTS will list the privileges granted to the account.

Run this script to create the SHOW GRANTS script for each user: 
MariaDB> SELECT DISTINCT CONCAT( 'SHOW GRANTS FOR ', user,'@', host,';') AS grantQuery FROM mysql.user WHERE is_role = 'N';

Run each SHOW GRANTS command for each user.
 
2. Only DEFINERS of routines (functions and procedures) can change routines. To view the DEFINERS of all functions and procedures, as database administrator run the following SQL:
 
MariaDB>  SELECT * FROM mysql.proc \\G
 
3. Only DEFINERS of triggers can change triggers. To view all triggers and their DEFINERS, as database administrator run the following SQL: 

MariaDB>  SELECT * FROM information_schema.triggers \\G
 
4. Views: At view definition time, the view creator must have the privileges needed to use the top-level objects accessed by the view. For example, if the view definition refers to table columns, the creator must have privileges for the columns, as described previously. If the definition refers to a stored function, only the privileges needed to invoke the function can be checked. The privileges required when the function runs can be checked only as it executes. For different invocations of the function, different execution paths within the function might be taken.

If any such permissions exist and are not documented and approved, this is a finding."
  desc 'fix', 'Document and obtain approval for any nonadministrative users who require the ability to create, alter, or replace logic modules.

Check the security guide to implement the approved permissions. Revoke any unapproved permissions.'
  impact 0.5
  ref 'DPMS Target MariaDB Enterprise 10.x'
  tag check_id: 'C-57183r841716_chk'
  tag severity: 'medium'
  tag gid: 'V-253731'
  tag rid: 'SV-253731r841718_rule'
  tag stig_id: 'MADB-10-007800'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag fix_id: 'F-57134r841717_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
