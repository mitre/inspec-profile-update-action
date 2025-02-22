control 'SV-223751' do
  title 'IBM z/OS JESNEWS resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
RL OPERCMS *

JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem.

If the JES2.UPDATE.JESNEWS resource is defined to the OPERCMDS resource class, this is not a finding. 

If access authorization to the JES2.UPDATE.JESNEWS resource in the OPERCMDS class restricts CONTROL access to the appropriate personnel (i.e., users responsible for maintaining the JES News data set), this is not a finding.

If all access to the JES2.UPDATE.JESNEWS resource is logged, this is not a finding.'
  desc 'fix', %q(Refer to "Protecting JESNEWS" in Chapter 7 of the JES2 Init & Tuning Guide.

a) Ensure the following items are in effect:

1) The JES2.UPDATE.JESNEWS resource is defined to the OPERCMDS resource class with a default access of NONE and all access is logged.

NOTE: JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem.

2) Access authorization to the JES2.UPDATE.JESNEWS resource in the OPERCMDS class restricts CONTROL access to the appropriate personnel (i.e., users responsible for maintaining the JES News data set) and all access is logged.

Examples of setting up proper protection are shown here:

RDEF OPERCMDS JES2.UPDATE.JESNEWS UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) DATA('COMPLY WITH ZJES0042')

PERMIT JES2.UPDATE.JESNEWS CLASS(OPERCMDS) ID(<syspsmpl>) ACCESS(CONTROL))
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25424r514941_chk'
  tag severity: 'medium'
  tag gid: 'V-223751'
  tag rid: 'SV-223751r604139_rule'
  tag stig_id: 'RACF-JS-000070'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25412r514942_fix'
  tag 'documentable'
  tag legacy: ['V-98209', 'SV-107313']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
