control 'SV-251250' do
  title 'Redis Enterprise DBMS and associated applications must reserve the use of dynamic code execution for situations that require it.'
  desc 'With respect to database management systems, one class of threat is known as code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of LUA and SQL. In such cases, the attacker deduces the manner in which code is processed, either from inside knowledge or by observing system behavior in response to invalid inputs. When the attacker identifies scenarios where code is executed dynamically, the attacker is then able to craft input strings that subvert it. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

The principal protection against code injection is not to use dynamic execution except where it provides necessary functionality that cannot be used otherwise. Use strongly typed data items rather than general-purpose strings as input parameters to task-specific, pre-compiled stored procedures and functions (and triggers).

Because Redis does not rely on a query language, there is no known method of SQL injection that would apply to Redis. Redis is a key value store and relies on commands that do not have a unified query language. Redis does have an embedded LUA interpreter and the user will need to disable these.

When dynamic execution is necessary, ways to mitigate the risk include the following, which should be implemented both in the on-screen application and at the database level, in the stored procedures:
- Allow strings as input only when necessary. 
- Rely on data typing to validate numbers, dates, etc. Do not accept invalid values. If substituting other values for them, think carefully about whether this could be subverted.
- Limit the size of input strings to what is truly necessary.
- If single quotes/apostrophes, double quotes, semicolons, equals signs, angle brackets, or square brackets will never be valid as input, reject them.
- If comment markers will never be valid as input, reject them. 
- If HTML and XML tags, entities, comments, etc., will never be valid, reject them.
- If wildcards are present, reject them unless truly necessary. 
- If there are range limits on the values that may be entered, enforce those limits.
- Institute procedures for inspection of programs for correct use of dynamic coding by a party other than the developer.
- Conduct rigorous testing of program modules that use dynamic coding, searching for ways to subvert the intended use.
- Record the inspection and testing in the system documentation.
- Bear in mind that all this applies not only to screen input, but also to the values in an incoming message to a web service or to a stored procedure called by a software component that has not itself been hardened in these ways. Not only can the caller be subject to such vulnerabilities, but it may also itself be the attacker.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed and must document what has been discovered.'
  desc 'check', "Redis does not rely on a query language and there is no known method of SQL injection that would apply to Redis. Redis is a key value store and relies on commands that do not have a unified query language. Redis has an embedded LUA interpreter that is recommended to disable.

Interview the system administrator and ask if the practice of disabling LUA scripting is a documented practice or has been completed. To check if LUA scripting is disabled on the desired database:
1. Connect to one of the nodes/servers in the redis enterprise cluster as an admin (sudo su -).
2. Type: rladmin status to get the DB ID of the  database on which LUA scripting is to be disabled
3. Run the following command, substituting in the bdb_id from the previous step: 
ccs-cli hget bdb:<bdb_id> 

If the response is NIL or doesn't return EVAL, EVALSHA, this is a finding.

If no documentation exists or if the database otherwise accepts LUA scripts, this is a finding."
  desc 'fix', %q(Redis does not rely on a query language and there is no known method of SQL injection that would apply to Redis. Redis is a key value store and relies on commands that do not have a unified query language. Redis has an embedded LUA interpreter that is recommended to disable.

To disable the interpreter run the following REST API command:
curl -v -kL -u "<user>:<password>" --location-trusted -H "Content-type: application/json" -d '{ "disabled_commands": "EVAL, EVALSHA" }' -X PUT https://<URL>:PORT/v1/bdbs/<DB_ID>)
  impact 0.5
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54685r804938_chk'
  tag severity: 'medium'
  tag gid: 'V-251250'
  tag rid: 'SV-251250r804940_rule'
  tag stig_id: 'RD6X-00-011900'
  tag gtitle: 'SRG-APP-000251-DB-000391'
  tag fix_id: 'F-54639r804939_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
