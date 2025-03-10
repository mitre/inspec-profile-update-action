control 'SV-223644' do
  title 'IBM z/OS System data sets used to support the VTAM network must be properly secured.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

'
  desc 'check', 'Create a list of data set names containing all VTAM start options, configuration lists, network resource definitions, commands, procedures, exit routines, all SMP/E TLIBs, and all SMP/E DLIBs used for installation and in development/production VTAM environments.

If ACF2 data set rules for all VTAM system data sets do not restrict access to only network systems programming staff, this is a finding.
If ACF2 data set rules for all VTAM system data sets do not restrict auditors to READ access only, this is a finding.

These data sets include libraries containing VTAM load modules and exit routines, and VTAM start options and definition statements.'
  desc 'fix', 'Define ACF2 data set rules for all VTAM system data sets to restrict access to only network systems programming staff.
Auditors may have READ access as documented and approved by ISSM.

These data sets include libraries containing VTAM load modules and exit routines, and VTAM start options and definition statements.

Example:
$KEY(SYS1)
VTAM-.- UID(sysprgmr) R(A) W(L) A(L) E(A)

$KEY(S3V) 
$PREFIX(SYS3)
VTAM-.- UID(sysprgmr) R(A) W(L) A(L) E(A)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25317r504878_chk'
  tag severity: 'medium'
  tag gid: 'V-223644'
  tag rid: 'SV-223644r533198_rule'
  tag stig_id: 'ACF2-VT-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25305r504879_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-97993', 'SV-107097']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
