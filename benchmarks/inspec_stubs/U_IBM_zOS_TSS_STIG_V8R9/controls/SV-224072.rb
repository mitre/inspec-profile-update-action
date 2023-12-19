control 'SV-224072' do
  title 'IBM Z/OS TSOAUTH resources must be restricted to authorized users.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS TSOAUTH(*)

For each resource defined enter:
TSS WHOHAS(<tsoauth resource>)

If the following guidance is true, this is not a finding.

-The ACCT authorization is restricted to security personnel.
-The CONSOLE authorization is restricted to authorized systems personnel (e.g., systems programming personnel, operations staff, etc.) and READ access may be given to all user when SDSF in install at the ISSOs discretion.
-The MOUNT authorization is restricted to DASD batch users only.
-The OPER authorization is restricted to authorized systems personnel (e.g., systems programming personnel, operations staff, etc.).
-The PARMLIB authorization is restricted to only z/OS systems programming personnel and READ access may be given to auditors.
-The TESTAUTH authorization is restricted to only z/OS systems programming personnel.'
  desc 'fix', "Configure the TSOAUTH resource class to control sensitive TSO/E commands.

Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.

Below is listed the access requirements for TSOAUTH resources. Ensure the guidelines for the resources and/or generic equivalent are followed.

-The ACCT authorization is restricted to security personnel.
-The CONSOLE authorization is restricted to authorized systems personnel (e.g., systems programming personnel, operations staff, etc.) and READ access may be given to all user when SDSF in install at the ISSOs discretion.
-The MOUNT authorization is restricted to DASD batch users only.
-The OPER authorization is restricted to authorized systems personnel (e.g., systems programming personnel, operations staff, etc.).
-The PARMLIB authorization is restricted to only z/OS systems programming personnel and READ access may be given to audit users.
-The TESTAUTH authorization is restricted to only z/OS systems programming personnel."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25745r516615_chk'
  tag severity: 'medium'
  tag gid: 'V-224072'
  tag rid: 'SV-224072r877910_rule'
  tag stig_id: 'TSS0-TS-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25733r869017_fix'
  tag 'documentable'
  tag legacy: ['SV-107955', 'V-98851']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
