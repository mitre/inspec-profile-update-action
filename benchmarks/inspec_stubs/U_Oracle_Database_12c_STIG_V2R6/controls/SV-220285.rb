control 'SV-220285' do
  title 'Unused database components, DBMS software, and database objects must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. Examples include, but are not limited to, installing advertising software, demonstrations, or browser plug-ins not related to requirements or providing a wide array of functionality not required for the mission.

Applications must adhere to the principles of least functionality by providing only essential capabilities.

Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.

Unused and unnecessary DBMS components increase the attack vector for the DBMS by introducing additional targets for attack. By minimizing the services and applications installed on the system, the number of potential vulnerabilities is reduced.'
  desc 'check', "Run this query to produce a list of components and features installed with the database:

SELECT comp_id, comp_name, version, status from dba_registry
WHERE comp_id not in ('CATALOG','CATPROC','XDB')
AND status <> 'OPTION OFF';

Review the list.  If unused components are installed and are not documented and authorized, this is a finding.

Starting with releases 11.1.0.7.x and above, all products are installed by default and the option to customize the product/component selection is no longer possible with the exception of those listed here:

Oracle JVM,
Oracle Text,
Oracle Multimedia,
Oracle OLAP,
Oracle Spatial,
Oracle Label Security, 
Oracle Application Express,
Oracle Database Vault"
  desc 'fix', 'If any components are required for operation of applications that will be accessing the DBMS, include them in the system documentation.

One cannot remove components, either via Database Configuration Assistant (DBCA) or manually once the database has been created, either from a container or a non-container database.

One can, however, use DBCA to create a non-container database and remove components during the creation process, before the database is created.

When using DBCA to create a custom non-container database, select
creation mode = advanced
Database Template = Custom
Database Options..Database Component.

Components that can be selected or de-selected are:
Oracle JVM, Oracle Text, Oracle Multimedia, Oracle OLAP, Oracle Spatial, Oracle Label Security, Oracle Application Express, Oracle Database Vault

For a container database (CDB), the CDB$ROOT must have all possible database components available.  This is because, when a pluggable database (PDB) is plugged into the CDB, the CDB must have the same components installed as the PDB.  Since we do not know what components the PDBS may have, the CDB must be able to support all possible PDB configurations.

Components installed in the CDB$ROOT do not need to be licensed.  Components are only considered to be used if they are installed in the PDB.

To configure a PDB to only use specific components, do the following:

1) Create a non-CDB 12.1 database and configure that database with the components desired.

2) Plug the non-CDB database into a CDB database, creating a new PDB.  If wanted, can then create additional clones from the new PDB.'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22000r666933_chk'
  tag severity: 'medium'
  tag gid: 'V-220285'
  tag rid: 'SV-220285r395853_rule'
  tag stig_id: 'O121-C2-011600'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-21992r391987_fix'
  tag 'documentable'
  tag legacy: ['SV-76169', 'V-61679']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
