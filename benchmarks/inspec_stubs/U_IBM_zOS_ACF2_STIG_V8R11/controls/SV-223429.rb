control 'SV-223429' do
  title 'CA-ACF2 NJE GSO record value must indicate validation options that apply to jobs submitted through a network job entry subsystem (JES2, JES3, RSCS).'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ACF input screen enter:
SET CONTROL(GSO)
LIST LIKE(NJE-)

If the GSO NJE record values conform to the following requirements, this is not a finding.

Specifies ACF2 validation options that apply to jobs submitted through a network job entry subsystem (JES2, JES3, RSCS).

 DFTLID() INHERIT NODEMASK(-) ENCRYPT VALIN(YES) NOVALOUT

NOTE: For NJE nodes that are incompatible with the XDES algorithm, discrete NJE records will be created with NOENCRYPT.
NOTE: Local changes will be documented in writing with supporting documentation.'
  desc 'fix', 'Configure ACF2 validation options that apply to jobs submitted through a network job entry subsystem (JES2, JES3, RSCS) as follows:

DFTLID()
INHERIT
NODEMASK(-)
ENCRYPT
VALIN(YES)
NOVALOUT

NOTE: For NJE nodes that are incompatible with the XDES algorithm, discrete NJE records will be created with NOENCRYPT.

NOTE: Local changes will be justified in writing with supporting documentation.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25102r504425_chk'
  tag severity: 'medium'
  tag gid: 'V-223429'
  tag rid: 'SV-223429r533198_rule'
  tag stig_id: 'ACF2-ES-000080'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25090r504426_fix'
  tag 'documentable'
  tag legacy: ['SV-106659', 'V-97555']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
