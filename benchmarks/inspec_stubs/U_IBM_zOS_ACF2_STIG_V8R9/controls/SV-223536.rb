control 'SV-223536' do
  title 'IBM z/OS Surrogate users must be controlled in accordance with proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'Review the ACFGSO report executionuserid.SUBMIT resources. These are usually defined to CLASMAP as TYPE(SUR).
NOTE: If CLASMAP defines SURROGAT as anything other than TYPE(SUR), replace SUR below with the appropriate three letters.

If no executionuserid.SUBMIT resources are defined to the SURROGAT resource class, this is not applicable.

If executionuserid.SUBMIT resources are defined to the SURROGAT resource class, review resource rules for TYPE(SUR). If the following items are in effect, this is not a finding.

All executionlogonid.SUBMIT resources defined to the SURROGAT class specify a default access of PREVENT.

All resource access is logged; at the discretion of the ISSM/ISSO, scheduling tasks may be exempted.

Access authorization is restricted to scheduling tools, started tasks, or other system applications required for running production jobs. 

Other users may have minimal access required for running production jobs with documentation properly approved and filed with the site security official (ISSM or equivalent).'
  desc 'fix', 'All executionuserid.SUBMIT resources defined to the SURROGAT resource class specify a default of no access; all resource access is logged (at the discretion of the ISSM/ISSO scheduling tasks may be exempted) and access authorization is restricted to the minimum number of personnel required for running production jobs.

Ensure the CLASMAP defines SURROGAT as TYPE(SUR).

NOTE: If CLASMAP defines SURROGAT as anything other than TYPE(SUR), replace SUR below with the appropriate three letters.

Ensure the following items are in effect:

All executionlogonid.SUBMIT resources defined to the SURROGAT class specify a default access of PREVENT.

All resource access is logged except for scheduling tasks.

Access authorization is restricted to scheduling tools, started tasks, or other system applications required for running production jobs.

Other users may have minimal access required for running production jobs with documentation properly approved and filed with the site security official (ISSM or equivalent). 

Consider the following recommendations when implementing security for Executionuserid.SUBMIT resources:

Keep the use of Executionuserid.SUBMIT resources outside of those granted to the scheduling software to a minimum number of individuals.

The simplest configuration is to only use Executionuserid.SUBMIT for the appropriate Scheduling task/software for production scheduling purposes as documented.

Temporary Cross Authorization of the production batch ACID to the scheduling tasks may be allowed for a period for testing by the appropriate specific production Support Team members. Authorization, eligibility, and test period is determined by site policy.

Access authorization is restricted to the minimum number of personnel required for running production jobs. However, Executionuserid.SUBMIT usage should not become the default for all jobs submitted by individual userids (i.e., system programmer must use their assigned individual userids for software installation, duties, whereas using a Executionuserid.SUBMIT resource would normally be for scheduled batch production only and as such must normally be limited to the scheduling task such as CONTROLM) and not granted as a normal daily basis to individual users.

Example:

$KEY(SRR) TYPE(SUR) 
SUBMIT UID(*******STC******CONTROLM) ALLOW
- UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25209r504663_chk'
  tag severity: 'medium'
  tag gid: 'V-223536'
  tag rid: 'SV-223536r853536_rule'
  tag stig_id: 'ACF2-JS-000090'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25197r504664_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000326-GPOS-00126']
  tag 'documentable'
  tag legacy: ['SV-106881', 'V-97777']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
