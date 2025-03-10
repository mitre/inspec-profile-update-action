control 'SV-252153' do
  title 'Database software, including DBMS configuration files, must be stored in dedicated directories, or DASD pools, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'By default MongoDB, runs using mongod user account (both user and group) and uses the following default directories:

MongoDB created directories (default):

/var/lib/mongo       (the data directory)
/var/lib/mongo/diagnostic.data
/var/lib/mongo/_tmp
/var/lib/mongo/journal

/var/log/mongodb     (the mongod process log directory)
/var/log/mongodb/audit    (the auditLog directory)

Standard directories:

/bin                    (the executable directory)
/etc                     (the configuration file directory)

Check if any non-MongoDB application, non-MongoDB data, or non-MongoDB directories exists under any of the MongoDB created directories or sub-directories.

If any non-MongoDB application, non-MongoDB data, or non-MongoDB directories exists under the MongoDB-created directories, this is a finding.'
  desc 'fix', 'The official installation packages from MongoDB segregates MongoDB executable software from MongoDB data directories by default.

For any non-MongoDB application found, reinstall that application to use directories that are not under the MongoDB-created directories. 

For any non-MongoDB application that stores data under the MongoDB created directories, reinstall the application and configure the application to use non-MongoDB-created directories to store its data.

For any non-MongoDB data that is found under the MongoDB created directories that cannot be associated with a MongoDB application, move or delete that data from the MongoDB-created directories.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55609r813839_chk'
  tag severity: 'medium'
  tag gid: 'V-252153'
  tag rid: 'SV-252153r813841_rule'
  tag stig_id: 'MD4X-00-002200'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-55559r813840_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
