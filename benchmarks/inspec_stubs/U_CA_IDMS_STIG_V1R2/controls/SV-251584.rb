control 'SV-251584' do
  title 'IDMS must allow only authorized users to sign on to an IDMS CV.'
  desc 'Unauthorized users signing on to IDMS can pose varying amounts of risk depending upon the security of the IDMS resources in an IDMS CV. Until the IDMS sign-on resource type (SGON) is secured anyone can sign on to IDMS. This risk can be mitigated by securing the SGON resource.'
  desc 'check', 'Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output. 

Note that this requires PTFs SO07995 and SO09476.

Look for a #SECRTT statement with the string "RESTYPE=SGON" and SECBY=EXTERNAL. 

If no "RESTYPE=SGON" is found or "SECBY=OFF" or "SECBY=INTERNAL" is specified, this is a finding.

Execute an external security manager (ESM) resource access list for resource "SGON" for each CV on the system.

If the resource access is not restricted to only users authorized in the site security plan, this is a finding.'
  desc 'fix', %q(In the source for RHDCSRTT add a #SECRTT entry to secure the sign-on process such as this example:

          #SECRTT TYPE=ENTRY,                                           X
                    RESTYPE=SGON,                                           X
                   SECBY=EXTERNAL,                                         X
                   EXTCLS='CA@IDMS',                                  X
                   EXTNAME=(RESTYPE,RESNAME)                                    

The RESNAME used during sign-on is the CV system name as defined in SYSGEN. To find the system name sign into SYSGEN in the CV. Then issue command "SIGNON DICT SYST" and then issue command "DISP SYS nnn" where nnn is the CV number. Look for "SYSTEM ID IS" to find the system name used as RESNAME.

Before implementing changes, contact the security administrator and ensure that the ESM has the necessary rules for the EXTCLS and EXTNAME values chosen. The appropriate ESM rules must then be given to the appropriate users. For instance, in Top Secret:
TSS PER(user_id) CA@IDMS(SGON.your_extname)

In ACF2:
$KEY(SGON.your_extname) TYPE(CA@IDMS) 
 UID(user_id) ALLOW

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:

DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
DCMT VARY NUCLEUS RELOAD)
  impact 0.7
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55019r807617_chk'
  tag severity: 'high'
  tag gid: 'V-251584'
  tag rid: 'SV-251584r807619_rule'
  tag stig_id: 'IDMS-DB-000030'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54973r807618_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
