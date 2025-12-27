control 'SV-213610' do
  title 'The EDB Postgres Advanced Server and associated applications, when making use of dynamic code execution, must scan input data for invalid values that may indicate a code injection attack.'
  desc "With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. In such cases, the attacker deduces the manner in which SQL statements are being processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where SQL queries are being assembled by application code (which may be within the database or separate from it) and executed dynamically, the attacker is then able to craft input strings that subvert the intent of the query. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

The principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be utilized otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).

When dynamic execution is necessary, ways to mitigate the risk include the following, which should be implemented both in the on-screen application and at the database level, in the stored procedures:
-- Allow strings as input only when necessary. 
-- Rely on data typing to validate numbers, dates, etc. Do not accept invalid values. If substituting other values for them, think carefully about whether this could be subverted.
-- Limit the size of input strings to what is truly necessary.
-- If single quotes/apostrophes, double quotes, semicolons, equals signs, angle brackets, or square brackets will never be valid as input, reject them.
-- If comment markers will never be valid as input, reject them. In SQL, these are -- or /* */ 
-- If HTML and XML tags, entities, comments, etc., will never be valid, reject them.
-- If wildcards are present, reject them unless truly necessary. In SQL these are the underscore and the percentage sign, and the word ESCAPE is also a clue that wildcards are in use.
-- If SQL key words, such as SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP, ESCAPE, UNION, GRANT, REVOKE will never be valid, reject them. Use case-insensitive comparisons when searching for these. Bear in mind that some of these words, particularly Grant (as a person's name), could also be valid input. 
-- If there are range limits on the values that may be entered, enforce those limits.
-- Institute procedures for inspection of programs for correct use of dynamic coding, by a party other than the developer.
-- Conduct rigorous testing of program modules that use dynamic coding, searching for ways to subvert the intended use.
-- Record the inspection and testing in the system documentation.
-- Bear in mind that all this applies not only to screen input, but also to the values in an incoming message to a web service or to a stored procedure called by a software component that has not itself been hardened in these ways. Not only can the caller be subject to such vulnerabilities; it may itself be the attacker.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered."
  desc 'check', 'Execute the following SQL as enterprisedb:

SELECT * FROM sqlprotect.list_protected_users;

If the database and user that handles user input is not listed or if sqlprotect.list_protected_users does not exist (meaning SQL/Protect is not installed), and an alternative means of reviewing for vulnerable code is not in use, this is a finding.'
  desc 'fix', 'Install and configure SQL/Protect as documented here: 

http://www.enterprisedb.com/docs/en/9.5/eeguide/Postgres_Plus_Enterprise_Edition_Guide.1.072.html#

Alternatively, implement, document, and maintain another method of checking for the validity of inputs.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14832r290142_chk'
  tag severity: 'medium'
  tag gid: 'V-213610'
  tag rid: 'SV-213610r508024_rule'
  tag stig_id: 'PPS9-00-006400'
  tag gtitle: 'SRG-APP-000251-DB-000392'
  tag fix_id: 'F-14830r290143_fix'
  tag 'documentable'
  tag legacy: ['SV-83577', 'V-68973']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
