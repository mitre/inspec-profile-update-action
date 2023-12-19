control 'SV-89145' do
  title 'Database software, including DBMS configuration files, must be stored in dedicated directories, separate from the host OS and other applications.'
  desc "When dealing with change control issues, it should be noted any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system.

Multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to host system directories can most likely lead to a compromise of all applications hosted by the same system. Database software not installed using dedicated directories both threatens and is threatened by other hosted applications. Access controls defined for one application may by default provide access to the other application's database objects or directories. Any method that provides any level of separation of security context assists in the protection between applications."
  desc 'check', 'The base installation directory of the database server software and the instance home directory location is configurable at the time of installation.

Run the db2ls command to find the installation directory of DB2 server software.

The environment variable INSTHOME points to instance home directory.

If there are non-DB2-related files in the instance home directory and the subsequent subdirectories under it, this is a finding. 

If there are non-DB2-related files in the DB2 install directory and the subsequent subdirectories under it, this is a finding.'
  desc 'fix', 'Remove the non-DB2 software from instance home directory and subdirectories.

Remove the non-DB2 software from DB2 installation directories and subdirectories.'
  impact 0.5
  ref 'DPMS Target IBM DB2 LUW 10.5 for Linux'
  tag check_id: 'C-74397r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74471'
  tag rid: 'SV-89145r1_rule'
  tag stig_id: 'DB2X-00-003100'
  tag gtitle: 'SRG-APP-000133-DB-000199'
  tag fix_id: 'F-81071r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
