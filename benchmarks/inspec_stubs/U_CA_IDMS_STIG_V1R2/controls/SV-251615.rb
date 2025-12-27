control 'SV-251615' do
  title 'The DBMS must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Non-organizational users include all information system users other than organizational users, which include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors, guest researchers, individuals from allied nations). 

Non-organizational users must be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access, such as accessing a web server. 

Accordingly, a risk assessment is used in determining the authentication needs of the organization. 

Scalability, practicality, and security are simultaneously considered in balancing the need to ensure ease of use for access to federal information and information systems with the need to protect and adequately mitigate risk to organizational operations, organizational assets, individuals, other organizations, and the Nation.'
  desc 'check', 'Check that sign-on has been secured. Examine load module RHDCSRTT by executing CA IDMS utility "IDMSSRTD", or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476.

Find the entry for sign-on by examining the entries. If no SGON entry exists (sign-on not secured), this is a finding. 

If found, but the entry is not secured externally, this is a finding. 

Verify the ESM entry for the externally secured "SGON" resource is correctly configured for the external resource class and the external name of the "SGON" resource in the SRTT. If not, this is a finding. 

If users, groups, and roles have not been appropriately defined to the external security manager (ESM), this is a finding.

Interrogate the security administrator and verify that only authorized users have permission through the ESM to access IDMS.

For local batch jobs that access database files, if there is no ESM security defined for the users submitting the jobs or securing the database datasets, this is a finding.'
  desc 'fix', %q(In the source for RHDCSRTT add a #SECRTT entry to secure the sign-on process using the ESM such as this example:

          #SECRTT TYPE=ENTRY,                                           X
                    RESTYPE=SGON,                                           X
                   SECBY=EXTERNAL,                                         X
                   EXTCLS='CA@IDMS',                                  X
                   EXTNAME=(RESTYPE,RESNAME)                             

The RESNAME used during sign on is the CV system name as defined in SYSGEN. To find the system name, sign in to SYSGEN in the CV. Then, issue commands "SIGNON DICT SYST" and "DISP SYS nnn" (where nnn is the CV number). Look for "SYSTEM ID IS" to find the system name used as RESNAME.

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:
 
   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY
   DCMT VARY NUCLEUS RELOAD

Before implementing the changes, contact the security administrator and verify the ESM has the necessary rules for the EXTCLS and EXTNAME values chosen. The appropriate ESM rules must then be given to the appropriate users. For instance, in Top Secret:
TSS PER(user_id) CA@IDMS(SGON.the_extname)

In ACF2:
$KEY(SGON.the_extname) TYPE(CA@IDMS) 
 UID(user_id) ALLOW

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:

DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY
DCMT VARY NUCLEUS RELOAD

For local batch jobs, use OS-level security for job submission or secure database files using ESM dataset-level security.)
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55050r807710_chk'
  tag severity: 'medium'
  tag gid: 'V-251615'
  tag rid: 'SV-251615r807712_rule'
  tag stig_id: 'IDMS-DB-000350'
  tag gtitle: 'SRG-APP-000180-DB-000115'
  tag fix_id: 'F-55004r807711_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
