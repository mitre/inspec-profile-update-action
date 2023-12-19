control 'SV-251601' do
  title 'Database objects in an IDMS environment must be secured to prevent privileged actions from being performed by unauthorized users.'
  desc 'If database objects like areas, schemas, and run units are not secured, they may be changed or deleted by unauthorized users.'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476. 
 
Examine the SRTT and verify that entries exist for all desired database resources. The database resources that may be secured are and their respective RESTYPEs are:
Database                        - DB        
Area                                - AREA (1)
Rununit                          - NRU (1)
SQL Schema                  - QSCH (1)
Non-SQL Schema         - NSCH (1)
Access Module             - DACC (1) 
Table                              - TABL (1)
DMCL                             - DMCL
Database name table  - DBTB

Note: Securing RESTYPE=DB (Database) also secures for these resource types. SRTT TYPE=ENTRY statements with RESTYPEs of AREA, NRU, QSRCH, NSCH, DACC, and TABL do not turn security on or off for these RESTYPEs, but are used to build the EXTNAME and EXTCLAS to be passed to the external security manager (ESM).

Interrogate the DBA(s) to determine which database objects may need secured.

For SQL access, check that both the catalog and user database are secured in the SRTT. If not, this is a finding.

If batch jobs are allowed to be run with access an IDMS database, check whether the access is covered by standard ESM dataset security and/or the user-written exit 14 (issues a security check when a BIND RUN-UNIT or READY AREA is being done). If not, this is a finding.'
  desc 'fix', "Before securing a database externally, it is VERY IMPORTANT to weigh the following considerations:
- If adding an SRTT TYPE=ENTRY that secures the DB resource type externally, it automatically secures a group of database resource types externally for all databases.

- If the SRTT contains one or more TYPE=OCCUR (occurrence overrides) that specify external security for resource type DB, also add an SRTT entry specifying external resource class and external resource name for each of the database resource types that are automatically secured externally for the database being secured in that TYPE=OCCUR statement.

- The only database-related RESTYPE valid with TYPE=OCCUR is DB.

See the IDMS Techdocs for more information on securing database resources.

The SRTT module must have an entry coded to secure one or more database resources. For instance:

 #SECRTT TYPE=INITIAL,                         x
  ENVNAME=SYS001

 #SECRTT TYPE=ENTRY,                           X
   RESTYPE=DB,                                           X
   SECBY=OFF,                                              X
   EXTNAME=(ENVIR,RESNAME,RESTYPE),     X
   EXTCLS='CA@IDMS'
 
 #SECRTT TYPE=OCCUR,                         X
   RESTYPE=DB,                                           X
   SECBY=EXTERNAL ,                                X
   RESNAME='PROD'

The above example could be used to secure external name of SYS001.PROD.DB.

When securing SQL access, it is necessary to secure both the DBNAME containing the catalog segment (probably SYSSQL in APPLDICT) and the database being accessed.

 #SECRTT  TYPE=OCCUR,SECBY=EXT,RESTYPE=DB,  X
    RESNAME=APPLDICT'
#SECRTT  TYPE=OCCUR,SECBY=EXT,RESTYPE=DB,  X
    RESNAME='USERDB'

Because the above example also secures the DB subtypes, add SRTT entries to allow the ability to grant or deny access to them:

 #SECRTT TYPE=ENTRY,RESTYPE=AREA,    X
     SECBY=EXT,EXTNAME=(ENVIR,RESTYPE,RESNAME)
 #SECRTT TYPE=ENTRY,RESTYPE=NRU,     X
     SECBY=EXT,EXTNAME=(ENVIR,RESTYPE,RESNAME)
 #SECRTT TYPE=ENTRY,RESTYPE=QSCH,    X
     SECBY=EXT,EXTNAME=(ENVIR,RESTYPE,RESNAME)
 #SECRTT TYPE=ENTRY,RESTYPE=NSCH,    X
     SECBY=EXT,EXTNAME=(ENVIR,RESTYPE,RESNAME)
 #SECRTT TYPE=ENTRY,RESTYPE=DACC,    X
     SECBY=EXT,EXTNAME=(ENVIR,RESTYPE,RESNAME)
 #SECRTT TYPE=ENTRY,RESTYPE=TABL,    X
     SECBY=EXT,EXTNAME=(ENVIR,RESTYPE,RESNAME)

Note that the TABL resource type represents base tables, functions, procedures, table procedures, and views. 

Ensure that the ESM has a corresponding entry to give access to the desired users. For instance, in Top Secret:
TSS PER(user_id) CA@IDMS(SYS001.PROD.DB) ACCESS(access_level)
and assuming that the user wants to grant access to the area:
TSS PER(user_id) CA@IDMS(SYS001.PROD.AREA) ACCESS(access_level)"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55036r807668_chk'
  tag severity: 'medium'
  tag gid: 'V-251601'
  tag rid: 'SV-251601r807670_rule'
  tag stig_id: 'IDMS-DB-000210'
  tag gtitle: 'SRG-APP-000133-DB-000200'
  tag fix_id: 'F-54990r807669_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
