control 'SV-251617' do
  title 'CA IDMS must isolate the security manager to which users, groups, roles are assigned authorities/permissions to resources.'
  desc 'An isolation boundary provides access control and protects the integrity of the hardware, software, and firmware that perform security functions.

Security functions are the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based.

Developers and implementers can increase the assurance in security functions by employing well-defined security policy models; structured, disciplined, and rigorous hardware and software development techniques; and sound system/security engineering principles.

Database Management Systems typically separate security functionality from non-security functionality via separate databases or schemas. Database objects or code implementing security functionality should not be commingled with objects or code implementing application logic. When security and non-security functionality are commingled, users who have access to non-security functionality may be able to access security functionality.'
  desc 'check', 'Identify CA IDMS security domains (a set of DC systems and local mode applications sharing a single user catalog and SRTT). For a given security domain, log on to one DC system. Issue DCPROFIL. If there is nothing specified for "Security System" and therefore no external security system being used, this is a finding.

Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output.

Note: This requires PTFs SO07995 and SO09476.

If any entries have SECBY=INTERNAL, this is a finding.

For local batch jobs (i.e., those jobs that access database files without going through the CA IDMS system), dataset-level security should be defined in the external security manager (ESM) with authorizations according the site security plan. If it is not, this is a finding.

Check those resources that are secured externally to make sure the mapping to the ESM is correct. Check that the ESM entry for the externally secured resource is correctly configured for the external resource class and the external name of the resource being secured. The external name must match the format of the external name construction tokens found in the entry. If the ESM specification does not match the RHDCSRTT entry, this is a finding.'
  desc 'fix', 'In the internally secured entries that are to be changed to external security, change the #SECRTT parms SECBY=INTERNAL to SECBY=EXTERNAL. Add the parameters EXTCLS and EXTNAME to the entry using the resource class and name defined in the ESM. For instance: 

#SECRTT TYPE=ENTRY,SECBY=EXTERNAL,              X
 RESTYPE=restype,EXTCLS=CA@IDMS,                 X
 EXTNAME=(extname_definition)

Secure the resources through the ESM chosen by the organization (e.g., TSS, ACF 2, RACF) using the EXTCLS and the EXTNAME defined in the SRTT on the entry for the resource type. EXTCLS maps the CA IDMS resource type to the resource class defined in the external security system. The EXTNAME defines the format of the resource name defined to the ESM. 

Interrogate the security office regarding current and needed rules and definitions in the ESM. Define the users, groups, roles access to the resource in the ESM. For local batch jobs that access database files, define appropriate dataset-level security through the ESM. 

For example, in Top Secret:
TSS ADDTO(restype) CA@IDMS(SYST)
TSS PER(user_id) CA@IDMS(restype.the_extname)

In ACF2:
$KEY(restype.the_extname) TYPE(CA@IDMS) 
 UID(user_id) ALLOW

RDEFINE CA@IDMS restype UACC(NONE)
PERMIT restype.the_extname CLASS(CA@IDMS) ID(user_id) ACCESS(READ)

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:       
 
   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55052r807716_chk'
  tag severity: 'medium'
  tag gid: 'V-251617'
  tag rid: 'SV-251617r807718_rule'
  tag stig_id: 'IDMS-DB-000460'
  tag gtitle: 'SRG-APP-000233-DB-000124'
  tag fix_id: 'F-55006r807717_fix'
  tag 'documentable'
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
