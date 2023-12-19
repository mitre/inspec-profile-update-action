control 'SV-251608' do
  title 'The EMPDEMO databases, database objects, and applications must be removed.'
  desc 'Demonstration and sample database objects and applications present publicly known attack points for malicious users. These demonstration and sample objects are meant to provide simple examples of coding specific functions, and are not developed to prevent vulnerabilities from being introduced to the DBMS and host system.'
  desc 'check', 'If a CAISAG base installation completed with EMPDEMO=YES and/or SQLDEMO=YES, or if a base installation completed with CSM and CREATE_DB_DEMO and/or CREATE_SQL_DEMO selected, this is a finding. 

In OCF/BCF, DISPLAY DMCL <dmclname>. If segments EMPDEMO, SQLDEMO, and/or PROJDEMO exist, this is a finding. 

In OCF/BCF, DISPLAY DBTABLE <dbtbname>. If segments EMPDEMO, SQLDEMO, and/or PROJDEMO exist, this is a finding.

In OCF/BCF, DISPLAY SCHEMA DEMOEMPL and DISPLAY SCHEMA DEMOPROJ. If either or both exist, this is a finding. If schema EMPSCHM exists, this is a finding. 
                                                                                                                                                                                                                                                                                                                                                                                                                                    
If any of the following load modules are in load libs used by the installation, this is a finding:
EMPSS01, EMPDMCL, EMPLOAD, EMPRPT, EMPINQ

If any of the following files are found to be used by the installation, this is a finding:
<installation prefix>.EMPDEMO.EMPDEMO. <installation prefix>.EMPDEMO.INSDEMO, <installation prefix>.ORGDEMO.EMPDEMO, <installation prefix>.SQLDEMO.EMPLDEMO, <installation prefix>.SQLDEMO.INDXDEMO, <installation prefix>.SQLDEMO.INFODEMO, <installation prefix>.PROJSEG.PROJDEMO'
  desc 'fix', 'In OCF/BCF, ALTER DMCL <dmclname> and EXCLUDE SEGMENT EMPDEMO, SQLDEMO and/or PROJDEMO. Generate, punch, and relink dmcl. Do the same for DBTABLE <dbtbname>.

Remove load modules EMPSS01, EMPDMCL, EMPLOAD, EMPRPT, and EMPINQ from installation load libraries.
                                                                                                                                                                                                                                                                                                                                        
Remove files <installation prefix>.EMPDEMO.EMPDEMO. <installation prefix>.EMPDEMO.INSDEMO, <installation prefix>.ORGDEMO.EMPDEMO, <installation prefix>.SQLDEMO.EMPLDEMO, <installation prefix>.SQLDEMO.INDXDEMO, <installation prefix>.SQLDEMO.INFODEMO, <installation prefix>.PROJSEG.PROJDEMO from installation and installation JCL.

Remove database demo objects from application dictionaries including EMPSCHM record elements and records, EMPSS01, and schemas DEMOEMPL and DEMOPROJ, dropping all the tables in theses schemas.                                                                                               

For future base installs, specify EMPDEMO=NO and SQLDEMO=NO for CAISAG installs and do not select CREATE_DB_DEMO and CREATE_SQL_DEMO fields on CSM installs.                                                                                                                                                                                                                                                                                                                                                                                           

Note that specified names are default names. Use modified names if they were changed during base installation.'
  impact 0.3
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55043r807689_chk'
  tag severity: 'low'
  tag gid: 'V-251608'
  tag rid: 'SV-251608r807691_rule'
  tag stig_id: 'IDMS-DB-000280'
  tag gtitle: 'SRG-APP-000141-DB-000090'
  tag fix_id: 'F-54997r807690_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
