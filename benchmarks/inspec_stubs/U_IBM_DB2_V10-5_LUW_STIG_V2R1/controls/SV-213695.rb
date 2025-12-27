control 'SV-213695' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'On UNIX/LINUX, run the db2ls command to find all install paths of DB2 on the system:

     $db2ls

Run the db2ls command to find installed features of database on install paths:

     $db2ls -q -b <db2 install path>

If there are installed features which are not required by the mission objectives and are non-essential, this is a finding.

On Windows, go to Registry Editor in Windows.
Then select Computer >> HKEY_LOCAL_MACHINE >> SOFTWARE >> IBM >> DB2 >> COMPONENTS 
If there are installed features which are not required by the mission objectives and are non-essential, this is a finding.

Example: 
     db2ls -q -b /opt/ibm/db2/V10.5
Install Path : /opt/ibm/db2/V10.5

Feature Response File ID             Level   Fix Pack   Feature Description  
----------------------------------------------------------------------------------------------------
BASE_CLIENT                         10.5.0.7          7   Base client support 
JAVA_SUPPORT                        10.5.0.7          7   Java support 
SQL_PROCEDURES                      10.5.0.7          7   SQL procedures 
BASE_DB2_ENGINE                     10.5.0.7          7   Base server support 
CONNECT_SUPPORT                     10.5.0.7          7   Connect support 
DB2_DATA_SOURCE_SUPPORT             10.5.0.7          7   DB2 data source support 
SPATIAL_EXTENDER_SERVER_SUPPORT     10.5.0.7          7   Spatial Extender server support 
JDK                                 10.5.0.7          7   IBM Software Development Kit (SDK) for Java(TM) 
LDAP_EXPLOITATION                   10.5.0.7          7   DB2 LDAP support 
INSTANCE_SETUP_SUPPORT              10.5.0.7          7   DB2 Instance Setup wizard 
ACS                                 10.5.0.7          7   Integrated Flash Copy Support 
SPATIAL_EXTENDER_CLIENT_SUPPORT     10.5.0.7          7   Spatial Extender client 
COMMUNICATION_SUPPORT_TCPIP         10.5.0.7          7   Communication support - TCP/IP 
APPLICATION_DEVELOPMENT_TOOLS       10.5.0.7          7   Base application development tools 
DB2_UPDATE_SERVICE                  10.5.0.7          7   DB2 Update Service 
REPL_CLIENT                         10.5.0.7          7   Replication tools 
TEXT_SEARCH                         10.5.0.7          7   DB2 Text Search 
INFORMIX_DATA_SOURCE_SUPPORT        10.5.0.7          7   Informix data source support 
ORACLE_DATA_SOURCE_SUPPORT          10.5.0.7          7   Oracle data source support 
FIRST_STEPS                         10.5.0.7          7   First Steps 
GUARDIUM_INST_MNGR_CLIENT           10.5.0.7          7   Guardium Installation Manager Client'
  desc 'fix', 'On UNIX/Linux, run the following db2_deinstall command to remove the non-essential features:

     $db2_deinstall –F <feature>

Note: The db2_deinstall command is located at DB2DIR/install, where DB2DIR is the location where the current version of the DB2 database product is installed. (If uncertain of the value to provide for DB2DIR, find it using the db2level command.

On Windows, run the db2unins command to remove one or more db2 product, feature or languages. 
   
     >>-db2unins –p product     (to remove db2 product) 
         or 
     >>-db2unins –u response-file     (to remove db2 product, feature or languages.)

Note: 
Use the following URL to access the knowledgebase documentation on the db2_deinstall command: 
http://www.ibm.com/support/knowledgecenter/en/SSEPGG_10.5.0/com.ibm.db2.luw.admin.cmd.doc/doc/r0023670.html

Use the following URL to access the knowledgebase documentation on the db2unins command: 
http://www-01.ibm.com/support/knowledgecenter/SSEPGGman db2__10.5.0/com.ibm.db2.luw.admin.cmd.doc/doc/r0023371.html?lang=en'
  impact 0.5
  ref 'DPMS Target IBM DB2 V10.5 LUW'
  tag check_id: 'C-14916r295134_chk'
  tag severity: 'medium'
  tag gid: 'V-213695'
  tag rid: 'SV-213695r879587_rule'
  tag stig_id: 'DB2X-00-003500'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-14914r295135_fix'
  tag 'documentable'
  tag legacy: ['SV-89153', 'V-74479']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
