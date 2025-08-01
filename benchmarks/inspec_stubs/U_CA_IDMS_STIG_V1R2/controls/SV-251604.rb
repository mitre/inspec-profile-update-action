control 'SV-251604' do
  title 'Databases must be secured to protect from structural changes.'
  desc 'Database objects, like areas and run units, can be changed or deleted if not protected. Steps must be taken to secure these objects via the external security manager (ESM).

'
  desc 'check', 'All database objects to be secured must be specified to the CA IDMS centralized security in the security resource type table (SRTT) as being secured externally.

Log on to a DC system in the security domain. Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

Check each entry in the SRTT. If the resource type is DB, AREA, NRU, QSCH, NSCH, TABL, DACC, SACC, DMCL, or DBTB, the resource type is a database object. If it contains SECBY=INTERNAL, this is a finding. 

If any of the database types are not found in the SRTT, this is a finding.

For SQL access, check that both the catalog and user database are secured in the SRTT. If not, this is a finding.

If batch jobs are allowed to be run which access an IDMS database, check whether the access is covered by standard ESM dataset security and/or the user-written exit 14 (issues a security check at BIND/READY time). If not, this is a finding.
                                                     
If the ESM definition is correct but the role(s)/groups(s) are not defined correctly to give the appropriate permissions, this is a finding.'
  desc 'fix', 'Secure database object resources not found in SECRTT or found to be secured internally, through the ESM chosen by the organization (e.g., TSS, ACF 2, RACF).

Users, groups, roles, etc., are defined to the ESM, and it is here where the authorization for ownership is determined.

Once externally secured, create or modify the #SECRTT entries specify TYPE=ENTRY and TYPE=OCCURRENCE for the database resource type with the parameter of SECBY=EXTERNAL.

Use the RESTYPE DB which implicitly includes the subtypes AREA, NRU, QSCH, NSCH, TABL, DACC, and SACC. For each subtype, an entry must be added. The restypes for database tables and DMCLs are DBTB and DMCL, respectively.  

For SQL access, include #SECRTT RESTYPE=DB for  both the catalog and user database through all dbname and segment names that can access the catalog and database.                                                                                                                               

For batch jobs that access database objects, use the ESM standard dataset security and/or the user-written exit 14 to secure the database objects.

Create the corresponding entry in the ESM and give appropriate permissions to role(s)/ group(s) to allow database changes by appropriate users (usually DBAs).'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55039r807677_chk'
  tag severity: 'medium'
  tag gid: 'V-251604'
  tag rid: 'SV-251604r855263_rule'
  tag stig_id: 'IDMS-DB-000240'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-54993r807678_fix'
  tag satisfies: ['SRG-APP-000133-DB-000362', 'SRG-APP-000380-DB-000360']
  tag 'documentable'
  tag cci: ['CCI-001499', 'CCI-001813']
  tag nist: ['CM-5 (6)', 'CM-5 (1) (a)']
end
