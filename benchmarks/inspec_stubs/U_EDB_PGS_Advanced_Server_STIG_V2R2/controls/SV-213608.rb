control 'SV-213608' do
  title 'The EDB Postgres Advanced Server must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

Even when no such hijacking takes place, invalid input that gets recorded in the database, whether accidental or malicious, reduces the reliability and usability of the system. Available protections include data types, referential constraints, uniqueness constraints, range checking, and application-specific logic. Application-specific logic can be implemented within the database in stored procedures and triggers, where appropriate."
  desc 'check', 'Execute the following SQL as enterprisedb:

SELECT * FROM sqlprotect.list_protected_users;

If the database and user that handles user input is not listed or if sqlprotect.list_protected_users does not exist (meaning SQL/Protect is not installed), and an alternative means of reviewing for vulnerable code is not in use, this is a finding.'
  desc 'fix', 'Install and configure SQL/Protect as documented here: 

http://www.enterprisedb.com/docs/en/9.5/eeguide/Postgres_Plus_Enterprise_Edition_Guide.1.072.html#

Alternatively, implement, document, and maintain another method of checking for the validity of inputs.'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14830r290136_chk'
  tag severity: 'medium'
  tag gid: 'V-213608'
  tag rid: 'SV-213608r508024_rule'
  tag stig_id: 'PPS9-00-006200'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-14828r290137_fix'
  tag 'documentable'
  tag legacy: ['SV-83573', 'V-68969']
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
