control 'SV-251638' do
  title 'IDMS must protect its user catalogs and system dictionaries to prevent unauthorized users from bypassing or updating security settings.'
  desc 'Unauthorized access to user profiles, dictionaries, and user catalogs provides the ability to damage the IDMS system.'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

Confirm that the #SECRTT macro contains entries for the following resource names: UPRF for User Profile, SYSTEM for System Dictionary, SYSMSG for System Messages, and CATSYS for the User Catalog. 

If all of these resource names are not defined to external security, this is a finding.'
  desc 'fix', "Secure database object resources not found in SECRTT or found to be secured internally, through the external security manager (ESM) chosen by the organization (e.g., TSS, ACF 2, RACF). Users, groups, roles, etc., are defined to the ESM, and it is here where the authorization for ownership is determined. Once externally secured, create or modify the #SECRTT entries specify TYPE=ENTRY and TYPE=OCCURRENCE for the database resource type with the parameter of SECBY=EXTERNAL. Use the RESTYPE DB which implicitly includes the subtypes AREA, NRU, QSCH, NSCH, TABL, DACC, and SACC. For each subtype, an entry must be added. The restypes for database tables and DMCLs are DBTB and DMCL, respectively.

Update the #SECRTT macro to contain the following entries:
#SECRTT    TYPE=ENTRY,
      RESTYPE=UPRF,                                           X
      SECBY=EXTERNAL,                                         X
      Additional parameters required
#SECRTT TYPE=OCCURRENCE,                                      X
      RESNAME='SYSUSER',                                      X
      RESTYPE=DB,                                             X
      SECBY=EXTERNAL,                                         X
      Additional parameters required
#SECRTT TYPE=OCCURRENCE,                                      X
      RESTYPE=DB,                                             X
      RESNAME='SYSTEM',                                       X
      SECBY=EXTERNAL,                                         X
      Additional parameters required
#SECRTT TYPE=OCCURRENCE,                                      X
      RESTYPE=DB,                                             X
      RESNAME='SYSMSG',                                       X
      SECBY=EXTERNAL,                                         X
      Additional parameters required
#SECRTT TYPE=OCCURRENCE,                                      X
      RESTYPE=DB,                                             X
      RESNAME='CATSYS',                                       X
      SECBY=EXTERNAL,                                         X
      Additional parameters required

For batch jobs that access database objects, use the ESM standard dataset security and/or the user-written exit 14 to secure the database objects."
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55073r807779_chk'
  tag severity: 'medium'
  tag gid: 'V-251638'
  tag rid: 'SV-251638r855276_rule'
  tag stig_id: 'IDMS-DB-000670'
  tag gtitle: 'SRG-APP-000340-DB-000304'
  tag fix_id: 'F-55027r807780_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
