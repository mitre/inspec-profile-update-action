control 'SV-251646' do
  title 'The cache table procedures and views used for performance enhancements for dynamic SQL must be protected.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process.

When transmitting data, the DBMS, associated applications, and infrastructure must leverage transmission protection mechanisms.'
  desc 'check', 'For CA IDMS CV, issue "SELECT * FROM SYSCA.DSCCACHEOPT". If rows are returned, caching is on. 

For local, if no statement, SQL_CACHE_ENTRIES=0 exists in the SYSIDMS specification, caching is on. 

Examine RHDCSRTT in security domain for security on table procedures and views of DSCCACHE table; those supplied at installation (SYSCA.DSCCACHE, SYSCA.DSCCACHEOPT,SYSCA.DSCCACHECTRL, SYSCA.DSCCACHEV) or those created by organization. 

If no security is found for these table procedures and views, this is a finding.'
  desc 'fix', "Either turn off use of SQL cache or secure SQL cache tables.

Turn off SQL cache use in local using SYSIDMS parameter SQL_CACHE_ENTRIES=0. Turn off SQL cache use in IDMS CV and modify sysgen with statement DELETE SQL CACHE.
 
To secure SQL cache tables add RESTYPE DB entry and RESTYPE TABL occurrences for SQL cache tables (table procedures and views) SYSCA.DSCCACHE, SYSCA.DSCCACHEOPT,SYSCA.DSCCACHECTRL, SYSCA.DSCCACHEV) and any other views of SYSCA.DSCCACHE created by the organization.

For example: 
#SECRTT TYPE=ENTRY,RESTYPE=DB,EXTCLS='CA@IDMS',
  EXTNAME=(RESTYPE,ENVI,RESNAME),SECBY=OFF
 
#SECRTT  TYPE=ENTRY,RESTYPE=TABL,EXTCLS='CA@IDMS',
   EXTNAME=(ENVI,RESTYPE,SCHEMA,RESNAME),SECBY=EXTERNAL
                ... (other DB-covered ENTRYs e.g., NRU, DACC. etc.)  
  #SECRTT  TYPE=OCCUR,RESNAME='<db/segment to secure>',RESTYPE=DB,SECBY=EXTERNAL

Secure SQL cache tables in external security manager (ESM) using the corresponding chosen external name (e.g., PROD.TABL.SYSCA.DSCCACHE)."
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55081r807803_chk'
  tag severity: 'medium'
  tag gid: 'V-251646'
  tag rid: 'SV-251646r807805_rule'
  tag stig_id: 'IDMS-DB-000820'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-55035r807804_fix'
  tag 'documentable'
  tag cci: ['CCI-002420']
  tag nist: ['SC-8 (2)']
end
