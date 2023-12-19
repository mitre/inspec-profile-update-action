control 'SV-24359' do
  title 'Unused database components, database application software, and database objects should be removed from the DBMS system.'
  desc 'Unused, unnecessary DBMS components increase the attack surface for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.

However, dependencies exist among Oracle components that could result in the removal of an apparently unnecessary component interfering with the operation of a required component.  Therefore, thorough testing is required before removing components from a production server.'
  desc 'check', 'Use the Oracle Universal Installer or OPATCH utility to display the list of installed products. Review the list of installed products with the DBA and verify any installed products listed below are required and licensed. If any are installed and are not required or not licensed, this is a Finding.

From Command Prompt:
  $ORACLE_HOME/OPatch/opatch lsinventory –detail | more (UNIX)
  %ORACLE_HOME%/OPatch/opatch lsinventory –detail | more (Windows)

Requires additional License on Enterprise Edition:
Oracle Active Data Guard
Oracle Total Recall
Oracle Real Application Clusters
Oracle In-Memory Database Cache
Oracle Advanced Security
Oracle Label Security
Oracle Database Vault
Oracle Change Management Pack 
Oracle Configuration Management Pack
Oracle Diagnostic Pack
Oracle Tuning Pack
Oracle Provisioning and Patch Automation Pack
Oracle Real Application Testing
Oracle Partitioning
Oracle OLAP
Oracle Data Mining
Oracle Data Quality and Profiling
Oracle Data Watch and Repair Connector
Oracle Advanced Compression
Oracle Spatial
Oracle Content Database Suite

Requires additional License:
Oracle Database Gateways

Confirm requirements for these products:
Database Workspace Manager
Enterprise Manager Agent
iSQL*Plus
LDAP
Oracle Data Guard
Oracle Fail Safe (Windows only)
Oracle HTTP Server
Oracle interMedia
Oracle Internet Directory
Oracle Advanced Replication
Oracle Starter Database
Oracle Text
Oracle Virtual Private Database
Oracle Wallet Manager (Requires Advanced Security when using PKI and transparent encryption)
Oracle XML Development
Sample Schema

NOTE:  This list does not take into account product dependencies that, when selected for de-install, remove required database software. A custom installation without selection of unnecessary components is required to ensure a clean install of only required and licensed products. The list of product dependencies may be subject to change by Oracle and is not addressed here.'
  desc 'fix', 'Review the list of installed products available for the DBMS install. If any are required and licensed for operation of applications that will be accessing the DBMS, include them in the application design specification and list them in the System Security Plan. If any are not, but have been installed, uninstall them and remove any database schemas, objects, applications and security principals that exclusively support them.

Verify correct operation of the required Oracle components in a test environment before aplying these changes to a production system.'
  impact 0.3
  ref 'DPMS Target Oracle Homes 11g'
  tag check_id: 'C-26063r2_chk'
  tag severity: 'low'
  tag gid: 'V-3728'
  tag rid: 'SV-24359r2_rule'
  tag stig_id: 'DG0016-ORACLE11'
  tag gtitle: 'DBMS unused components'
  tag fix_id: 'F-23717r3_fix'
  tag responsibility: 'Database Administrator'
end
