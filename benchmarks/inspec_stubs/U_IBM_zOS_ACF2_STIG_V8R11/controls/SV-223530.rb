control 'SV-223530' do
  title 'IBM z/OS JESNEWS resources must be protected in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ACF command screen enter:
SET RESOURCE(OPR)
LIST LIKE(JES-)

If the JES2.UPDATE.JESNEWS resource is defined to the OPERCMDS resource class with a default access of PREVENT, this is not a finding.

NOTE: JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem.

If access authorization to the JES2.UPDATE.JESNEWS resource in the OPERCMDS class restricts DELETE service to the appropriate personnel (i.e., users responsible for maintaining the JES News data set) and all access is logged, this is not a finding.'
  desc 'fix', 'Configure the resource rules for the OPERCMDS resource class (i.e., TYPE(OPR)) and ensure the following items are in effect:

1) The JES2.UPDATE.JESNEWS resource is defined to the OPERCMDS resource class with a default access of PREVENT.

2) Access authorization to the JES2.UPDATE.JESNEWS resource in the OPERCMDS class restricts DELETE service to the appropriate personnel (i.e., users responsible for maintaining the JES News data set) and all access is logged.

Example:
$KEY(JES2) TYPE(OPR)
UPDATE.JESNEWS UID(SYSPROG) SERVICE(READ,UPDATE) LOG
UPDATE.JESNEWS UID(*) PREVENT'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25203r504645_chk'
  tag severity: 'medium'
  tag gid: 'V-223530'
  tag rid: 'SV-223530r533198_rule'
  tag stig_id: 'ACF2-JS-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25191r504646_fix'
  tag 'documentable'
  tag legacy: ['V-97765', 'SV-106869']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
