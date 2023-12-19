control 'SV-251607' do
  title 'CA IDMS must secure the ability to create, alter, drop, grant, and revoke user and/or system profiles to users or groups.'
  desc 'Even when using an external security manager (ESM), IDMS system and user profiles which reside in an IDMS user catalog may be assigned to users or groups. The ability to administer user and system profiles must be secured.'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476. 

Check the SRTT for externally secured RESTYPE=SYSA. If none is found, this is a finding. If the entry is secured internally, this is a finding.'
  desc 'fix', "The SRTT module must be coded to secure SYSADMIN. When using an ESM, this could be done in the following manner:
 
#SECRTT TYPE=ENTRY,                            X
 RESTYPE=SYSA,                                         X
 SECBY=EXTERNAL ,                                  X
 EXTNAME=(ENVIR,RESTYPE),              X
 EXTCLS='CA@IDMS'

Using the above example and supposing that was specified ENVNAME=TESTSYS on the INITIAL SRTT entry, the external resource name would be TESTSYS.SYSA. To give access using to a user in Top Secret the command would be:
TSS PER(user_id) CA@IDMS(TESTSYS.SYSA)

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:
 
DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
DCMT VARY NUCLEUS RELOAD"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55042r807686_chk'
  tag severity: 'medium'
  tag gid: 'V-251607'
  tag rid: 'SV-251607r807688_rule'
  tag stig_id: 'IDMS-DB-000270'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-54996r807687_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
