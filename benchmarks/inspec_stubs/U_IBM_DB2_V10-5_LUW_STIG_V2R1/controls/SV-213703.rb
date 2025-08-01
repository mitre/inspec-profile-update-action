control 'SV-213703' do
  title 'DB2 must separate user functionality (including user interface services) from database management functionality.'
  desc 'Information system management functionality includes functions necessary to administer databases, network components, workstations, or servers and typically requires privileged user access. 

The separation of user functionality from information system management functionality is either physical or logical and is accomplished by using different computers, different central processing units, different instances of the operating system, different network addresses, combinations of these methods, or other methods, as appropriate. 

An example of this type of separation is observed in web administrative interfaces that use separate authentication methods for users of any other information system resources. 

This may include isolating the administrative interface on a different domain and with additional access controls.

If administrative functionality or information regarding DBMS management is presented on an interface available for users, information on DBMS settings may be inadvertently made available to the user.'
  desc 'check', 'Run the following command to find the privileged groups and get the value of SYSADM_GROUP, SYSCTRL_GROUP, SYSMAINT_GROUP, SYSMON_GROUP:

     $db2 get dbm cfg 

If general users are part of any of above groups, this is a finding. 

On Windows systems, if the SYSADM_GROUP database manager configuration parameter is not specified, this is a finding.

Note: On UNIX to find the members of a group from the following two files or system admin utilities provided by LINUX/UNIX vendors. 

/etc/passwd
/etc/group
e.g. if value of SYSADM_GROUP is DB2IADM1 
From operating system files find out who is member of DB2IADM1

ON WINDOWS
You can use lusrmgr.msc or any other OS utility to manage user group memberships.'
  desc 'fix', 'Remove general users from the privileged groups, SYSADM_GROUP, SYSCTRL_GROUP, SYSMAINT_GROUP, SYSMON_GROUP using OS utilities/interface.

On Windows systems, set the SYSADM_GROUP database manager configuration parameter to the appropriate value.'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14924r295158_chk'
  tag severity: 'medium'
  tag gid: 'V-213703'
  tag rid: 'SV-213703r879631_rule'
  tag stig_id: 'DB2X-00-004800'
  tag gtitle: 'SRG-APP-000211-DB-000122'
  tag fix_id: 'F-14922r295159_fix'
  tag 'documentable'
  tag legacy: ['SV-89169', 'V-74495']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
