control 'SV-213609' do
  title 'The EDB Postgres Advanced Server and associated applications must reserve the use of dynamic code execution for situations that require it.'
  desc 'With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

The principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'Execute the following SQL as enterprisedb:

SELECT * FROM sqlprotect.list_protected_users;

If the database and user that handles user input is not listed or if sqlprotect.list_protected_users does not exist (meaning SQL/Protect is not installed), and an alternative means of reviewing for vulnerable code is not in use, this is a finding.'
  desc 'fix', 'Install and configure SQL/Protect as documented here: 

http://www.enterprisedb.com/docs/en/9.5/eeguide/Postgres_Plus_Enterprise_Edition_Guide.1.072.html#

Alternatively, implement, document, and maintain another method of checking for the validity of inputs.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14831r290139_chk'
  tag severity: 'medium'
  tag gid: 'V-213609'
  tag rid: 'SV-213609r508024_rule'
  tag stig_id: 'PPS9-00-006300'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-14829r290140_fix'
  tag 'documentable'
  tag legacy: ['SV-83575', 'V-68971']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
