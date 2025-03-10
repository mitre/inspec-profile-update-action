control 'SV-223755' do
  title 'IBM z/OS surrogate users must be controlled in accordance with proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From the ISPF Command Shell enter:
RList SURROGAT *

If no executionuserid.SUBMIT resources are defined to the SURROGAT resource class, this is Not Applicable.

For each executionuserid.SUBMIT resource defined to the SURROGAT resource class, if the following items are in true regarding surrogate controls, this is not a finding.

-All executionuserid.SUBMIT resources defined to the SURROGAT resource class specify a default access of NONE.
-All resource access is logged; at the discretion of the ISSM/ISSO scheduling tasks may be exempted.

Access authorization is restricted to scheduling tools, started tasks, or other system applications required for running production jobs.

Other users may have minimal access required for running production jobs with documentation properly approved and filed with the site security official (ISSM or equivalent).'
  desc 'fix', "Configure the SURROGAT as follows:
For executionuserid.SUBMIT resources defined to the SURROGAT resource class, ensure the following items are in effect regarding surrogate controls:

All executionuserid.SUBMIT resources defined to the SURROGAT resource class specify a default access of NONE.

All resource access is logged; at the discretion of the ISSM/ISSO scheduling tasks may be exempted.

Access authorization is restricted to scheduling tools, started tasks or other system applications required for running production jobs.

Other users may have minimal access required for running production jobs with documentation properly approved and filed with the site security official (ISSM or equivalent).

Consider the following recommendations when implementing security for Surrogate Users:

Keep the use of Surrogate Users outside of those granted to the scheduling software to a minimum number of individuals.

The simplest configuration is to only use Surrogate resource for the appropriate Scheduling task/software for production scheduling purposes as documented.

Temporary use of surrogate resource of the production batch to the scheduling tasks may be allowed for a period for testing by the appropriate specific production Support Team members. Authorization, eligibility, and test period are determined by site policy.

Access authorization is restricted to the minimum number of personnel required for running production jobs. However, Surrogate usage should not become the default for all jobs submitted by individual userids (i.e., system programmer must use their assigned individual userids for software installation, duties, whereas a Cross Authorized ACID would normally be utilized for scheduled batch production only and as such must normally be limited to the scheduling task such as CONTROLM) and not granted as a normal daily basis to individual users.

Command samples are provided to define/permit SURROGAT profiles:

SETR CLASSACT(SURROGAT)
SETR GENERIC(SURROGAT) GENCMD(SURROGAT)
SETR RACL(SURROGAT)

RDEF SURROGAT <batchid>.SUBMIT UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('SUBMIT JOBS FOR <batchid>, REFERENCE ZJES0060') 

PE <batchid>.SUBMIT CL(SURROGAT) ID(<authorized user such as CONTROLM>)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25428r514953_chk'
  tag severity: 'medium'
  tag gid: 'V-223755'
  tag rid: 'SV-223755r853608_rule'
  tag stig_id: 'RACF-JS-000110'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25416r514954_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000326-GPOS-00126']
  tag 'documentable'
  tag legacy: ['V-98217', 'SV-107321']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
