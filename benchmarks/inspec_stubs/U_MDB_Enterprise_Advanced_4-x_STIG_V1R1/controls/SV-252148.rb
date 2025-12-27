control 'SV-252148' do
  title 'MongoDB must limit the total number of concurrent connections to the database.'
  desc 'MongoDB must limit the total number of concurrent connections to the database.'
  desc 'check', 'Mongo can limit the total number of connections.

Verify that the MongoDB configuration file (default location: /etc/mongod.conf) contains the following:

net:
  maxIncomingConnections:  %int%      

If this parameter is not present, or the OS is not utilized to limit connections, this is a finding.'
  desc 'fix', 'MongoDB can limit the total number of connections served by mongod process by setting the following in the MongoDB configuration file (default location: /etc/mongod.conf)

net:
  maxIncomingConnections:  %int%      

See the following documentation:
https://docs.mongodb.com/v4.4/reference/configuration-options/

Products outside of MongoDB can be used to monitor database sessions and limit the maximum number of connections that can be made. 

Alternatively most UNIX-like operating systems, including Linux and macOS, provide ways to limit and control the usage of system resources such as threads, files, and network connections on a per-process and per-user basis. 

These ulimits prevent single users from using too many system resources. 

The following is the MongoDB documentation regarding these user limits: https://docs.mongodb.com/v4.4/reference/ulimit/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55604r813824_chk'
  tag severity: 'medium'
  tag gid: 'V-252148'
  tag rid: 'SV-252148r813826_rule'
  tag stig_id: 'MD4X-00-001550'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-55554r813825_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
