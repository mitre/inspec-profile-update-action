control 'SV-251612' do
  title 'The IDMS environment must require sign-on for users and restrict them to only authorized functions.'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system. 

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and any processes acting on behalf of users) must be uniquely identified and authenticated for all accesses, except the following:

(i) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and 
(ii) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals using shared accounts, for detailed accountability of individual activity.

The SGON resource must be protected to prevent unauthorized users from signing on.'
  desc 'check', 'For each CA IDMS system, verify the resource module RHDCSRTT for the security domain in which the CA IDMS system exists has an entry for sign-on. 

Examine load module RHDCSRTT by executing CA IDMS utility IDMSSRTD, or by issuing command "DCMT DISPLAY SRTT" while signed onto the CV, and reviewing the output. 

Note: This requires PTFs SO07995 and SO09476.

If no SGON entry exists (sign-on not secured), this is a finding. 

If found and the entry is not secured externally, this is a finding. 

Ensure the external security manager (ESM) entry for the externally secured "SGON" resource is correctly configured for the external resource class and the external name of the "SGON" resource. The external name must match the format of the external name construction tokens found in the SRTT entry. If not, this is a finding.

For local batch jobs that access database files, if there is no ESM security defined for the users submitting the jobs or securing the database datasets, this is a finding.'
  desc 'fix', %q(In the source for RHDCSRTT, add a #SECRTT entry to secure the sign-on process using the ESM such as this example:

          #SECRTT TYPE=ENTRY,                                           X
                    RESTYPE=SGON,                                           X
                   SECBY=EXTERNAL,                                         X
                   EXTCLS='CA@IDMS',                                  X
                   EXTNAME=(RESTYPE,RESNAME)                             

The RESNAME used during sign-on is the CV system name as defined in SYSGEN. To find the system name, sign in to SYSGEN in the CV. Then, issue the commands "SIGNON DICT SYST" and "DISP SYS nnn" (where nnn is the CV number). Look for "SYSTEM ID IS" to find the system name used as RESNAME. 

After making the above changes, assemble and link RHDCSRTT to create a new SRTT. To implement the new SRTT, either recycle any CVs that use the SRTT or issue these commands:

   DCMT VARY NUCLEUS MODULE RHDCSRTT NEW COPY 
   DCMT VARY NUCLEUS RELOAD

Before implementing changes, contact the security administrator and verify the ESM has the necessary rules for the EXTCLS and EXTNAME values chosen. The appropriate ESM rules must then be given to the appropriate users. For instance, in Top Secret:
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
  tag check_id: 'C-55047r807701_chk'
  tag severity: 'medium'
  tag gid: 'V-251612'
  tag rid: 'SV-251612r807703_rule'
  tag stig_id: 'IDMS-DB-000320'
  tag gtitle: 'SRG-APP-000148-DB-000103'
  tag fix_id: 'F-55001r807702_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
