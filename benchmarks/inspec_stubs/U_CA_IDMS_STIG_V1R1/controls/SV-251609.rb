control 'SV-251609' do
  title 'Default demonstration and sample databases, database objects, and applications must be removed.'
  desc 'Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions).

It is detrimental for software products to provide, or install by default, functionality exceeding requirements or mission objectives. 

DBMSs must adhere to the principles of least functionality by providing only essential capabilities.'
  desc 'check', 'If a CAISAG base installation done with EMPDEMO=YES and/or SQLDEMO=YES, or if a base installation done with CSM and CREATE_DB_DEMO and/or CREATE_SQL_DEMO selected, this is a finding.

In OCF/BCF, DISPLAY DMCL <dmclname>. If segments EMPDEMO, SQLDEMO and/or PROJDEMO exist, this is a finding.

In OCF/BCF, DISPLAY DBTABLE <dbtbname>. If segments EMPDEMO, SQLDEMO and/or PROJDEMO exist, this is a finding.

In OCF/BCF, DISPLAY SCHEMA DEMOEMPL and DISPLAY SCHEMA DEMOPROJ. If either or both exist, this is a finding. If schema EMPSCHM exists, this is a finding.
                                                                                                                                                                                                                                                                                                                                                                                                                                    
If any of the following load modules are in load libs used by the installation, this is a finding.
EMPSS01, EMPDMCL, EMPLOAD, EMPRPT, EMPINQ

If any of the following files are found to be used by the installation, this is a finding.
<installation prefix>.EMPDEMO.EMPDEMO. <installation prefix>.EMPDEMO.INSDEMO, <installation prefix>.ORGDEMO.EMPDEMO, <installation prefix>.SQLDEMO.EMPLDEMO, <installation prefix>.SQLDEMO.INDXDEMO, <installation prefix>.SQLDEMO.INFODEMO, <installation prefix>.PROJSEG.PROJDEMO'
  desc 'fix', 'In OCF/BCF, ALTER DMCL <dmclname> and EXCLUDE SEGMENT EMPDEMO, SQLDEMO and/or PROJDEMO. Generate, punch, and relink dmcl. Do the same for DBTABLE <dbtbname>.

Remove load modules EMPSS01, EMPDMCL, EMPLOAD, EMPRPT, and EMPINQ from installation load libraries.                                                                                                                                                                                                                                                                                                                                        

Remove files <installation prefix>.EMPDEMO.EMPDEMO. <installation prefix>.EMPDEMO.INSDEMO, <installation prefix>.ORGDEMO.EMPDEMO, <installation prefix>.SQLDEMO.EMPLDEMO, <installation prefix>.SQLDEMO.INDXDEMO, <installation prefix>.SQLDEMO.INFODEMO, <installation prefix>.PROJSEG.PROJDEMO from installation and installation jcl.

Remove database demo objects from application dictionaries including EMPSCHM and all the record elements and records, EMPSS01, schemas DEMOEMPL, and DEMOPROJ, dropping all the tables in theses schemas.

For future base installations, specify EMPDEMO=NO and SQLDEMO=NO for CAISAG installs and do not select CREATE_DB_DEMO and CREATE_SQL_DEMO fields on CSM installs.                                                                                                                                                                                                                                                                                                                                                                                          

Note that specified names are default names. Use modified names if they were changed during base installation.'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55044r807692_chk'
  tag severity: 'low'
  tag gid: 'V-251609'
  tag rid: 'SV-251609r807694_rule'
  tag stig_id: 'IDMS-DB-000290'
  tag gtitle: 'SRG-APP-000141-DB-000091'
  tag fix_id: 'F-54998r807693_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
