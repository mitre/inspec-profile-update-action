control 'SV-252167' do
  title 'MongoDB must check the validity of all data inputs except those specifically identified by the organization.'
  desc "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application.

With respect to database management systems, one class of threat is known as SQL Injection, or more generally, code injection. It takes advantage of the dynamic execution capabilities of various programming languages, including dialects of SQL. Potentially, the attacker can gain unauthorized access to data, including security settings, and severely corrupt or destroy the database.

Even when no such hijacking takes place, invalid input that gets recorded in the database, whether accidental or malicious, reduces the reliability and usability of the system. Available protections include data types, referential constraints, uniqueness constraints, range checking, and application-specific logic. Application-specific logic can be implemented within the database in stored procedures and triggers, where appropriate.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered."
  desc 'check', 'As a client program assembles a query in MongoDB, it builds a BSON object, not a string. Thus, traditional SQL injection attacks are not a problem. However, MongoDB operations permit arbitrary JavaScript expressions to be run directly on the server. 

To check, run the following command from the MongoDB shell: 

 db.col.find({ $where: "return true;"} ) 

If the response does not return an error, this is a finding. 

If JavaScript has been correctly disabled, the correct error would indicate that the JavaScript global engine has been disabled, e.g.:

Error: error: {
        "ok" : 0,
        "errmsg" : "no globalScriptEngine in $where parsing",
        "code" : 2,
        "codeName" : "BadValue"
}'
  desc 'fix', 'Disable the javascriptEnabled option in the %MongoDB configuration file% (default location: /etc/mongod.conf) to include the following:

security:
   javascriptEnabled: false

If document validation is needed, it should be configured according to the documentation page at:
https://docs.mongodb.com/v4.4/core/schema-validation/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55623r813881_chk'
  tag severity: 'medium'
  tag gid: 'V-252167'
  tag rid: 'SV-252167r813883_rule'
  tag stig_id: 'MD4X-00-004100'
  tag gtitle: 'SRG-APP-000251-DB-000160'
  tag fix_id: 'F-55573r813882_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
