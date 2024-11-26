control 'SV-235157' do
  title 'The MySQL Database Server 8.0 and associated applications must reserve the use of dynamic code execution for situations that require it.'
  desc 'With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

The principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).'
  desc 'check', 'Review MySQL source code (trigger procedures, functions) and application source code, to identify cases of dynamic code execution. Any user input should be handled through prepared statements or calls that bind parameters versus generating SQL.

If dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, this is a finding.'
  desc 'fix', 'Where dynamic code execution is employed in circumstances where the objective could practically be satisfied by static execution with strongly typed parameters, modify the code to do so.'
  impact 0.5
  ref 'DPMS Target Oracle MySQL 8.0'
  tag check_id: 'C-38376r623591_chk'
  tag severity: 'medium'
  tag gid: 'V-235157'
  tag rid: 'SV-235157r638812_rule'
  tag stig_id: 'MYS8-00-007400'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-38339r623592_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
