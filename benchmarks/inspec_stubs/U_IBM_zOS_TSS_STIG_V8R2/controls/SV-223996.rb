control 'SV-223996' do
  title 'IBM z/OS Surrogate users must be controlled in accordance with proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(ACIDS) DATA(XA)

If no XA ACID entries exist in the above reports, this is not applicable.

For each ACID identified in the XA ACID entries, if the following items are true regarding ACID permissions, this is not a finding.

-ACID permission (XA ACID) is logged (ACTION = AUDIT), only for Privileged USERIDS (MASTER, SCA, DCA, VCA, ZCA) if they are XAUTH; at the discretion of the ISSM/ISSO scheduling tasks may be exempted from logging.
-Access authorization is restricted to scheduling tools, started tasks or other system applications required for running production jobs.
-Other users may have minimal access required for running production jobs with documentation properly approved and filed with the site security official (ISSM or equivalent).'
  desc 'fix', 'For each ACID identified in the XA ACID entries, ensure the following items are in effect regarding ACID permissions:

-ACID permission (XA ACID) is logged (ACTION = AUDIT), at the discretion of the ISSM/ISSO scheduling tasks may be exempted from logging.
-ACID permission (XA ACID) is logged (ACTION = AUDIT), for Privileged users (MSCA, SCA, DCA, VCA, ZCA).
-Access authorization is restricted to scheduling tools, started tasks, or other system applications required for running production jobs.

Other users may have minimal access required for running production jobs with documentation properly approved and filed with the site security official (ISSM or equivalent). 

Consider the following recommendations when implementing security for Cross-Authorized ACIDs:

Keep ACID cross authorization of ACIDs outside of those granted to the scheduling software to a minimum number of individuals.

The simplest configuration is to have no ACID Cross Authorization except for the appropriate Scheduling task/software for production scheduling purposes as documented.

Temporary Cross Authorization of the production batch ACID to the scheduling tasks may be allowed for a period for testing by the appropriate specific production Support Team members. Authorization, eligibility, and test period is determined by site policy.

Access authorization is restricted to the minimum number of personnel required for running production jobs. However, ACID Cross Authorization usage must not become the default for all jobs submitted by individual userids (i.e., system programmer will use their assigned individual userids for software installation, duties, whereas a Cross-Authorized ACID would normally be utilized for scheduled batch production only and as such must normally be limited to the scheduling task such as CONTROLM) and not granted as a normal daily basis to individual users.

Grant access to the user ACID for each cross-authorized ACID required:

For Example:
TSS PERMIT(ACID) ACID(Cross-Authorized ACID) ACTION(AUDIT) 

For production ACIDs being used by CONTROLM:
TSS PER(CONTROLM)ACID(production user ACID)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25669r516387_chk'
  tag severity: 'medium'
  tag gid: 'V-223996'
  tag rid: 'SV-223996r561402_rule'
  tag stig_id: 'TSS0-JS-000120'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25657r516388_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000326-GPOS-00126']
  tag 'documentable'
  tag legacy: ['SV-107803', 'V-98699']
  tag cci: ['CCI-000213', 'CCI-002233']
  tag nist: ['AC-3', 'AC-6 (8)']
end
