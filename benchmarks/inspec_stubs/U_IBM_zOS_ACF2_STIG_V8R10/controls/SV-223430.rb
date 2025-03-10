control 'SV-223430' do
  title 'CA-ACF2 must protect Memory and privileged program dumps in accordance with proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From a command input screen enter:

SET RESOURCE (FAC) 
SET VERBOSE
LIST LIKE (IEAABD-)
NOTE: If CLASMAP defines FACILITY as anything other than the default of TYPE(FAC), replace FAC with the appropriate three letters.

If the IEAABD. resource and/or generic equivalent is defined with PREVENT access and that access is not available to any user, this is not a finding.

If the IEAABD.DMPAUTH. resource and/or generic equivalent is defined and access with SERVICE(READ) is limited to authorized users that have a valid job duties requirement for access, this is not a finding.

If the IEAABD.DMPAUTH. resource and/or generic equivalent is defined and access with the SERVICE(UPDATE) or greater is restricted to only systems personnel and that all access is logged, this is not a finding.

If the IEAABD.DMPAKEY. resource and/or generic equivalent is defined and all access is restricted to systems personnel and that all access is logged, this is not a finding.'
  desc 'fix', "Memory and privileged program dump resources are provided via resources in the FACILITY resource class. Ensure that the following are properly specified in the ACP.

(Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Below is listed the access requirements for memory and privileged program dump resources. Ensure the guidelines for the resource type, resources, and/or generic equivalent are followed. When protecting the facilities for dumps lists via the FACILITY resource class, ensure that the following items are in effect:

IEAABD.
IEAABD.DMPAUTH.
IEAABD.DMPAKEY.

The ACF2 resources are defined with a default access of PREVENT.

Ensure that no access is given to IEAABD. resource.

Example:
$KEY(IEAABD) TYPE(FAC)
- UID(*) PREVENT

IEAABD.DMPAUTH. READ access is limited to authorized users that have a valid job duties requirement for access. UPDATE access will be restricted to system programming personnel and access will be logged.

Example:
$KEY(IEAABD) TYPE(FAC)
DMPAUTH.- UID(sysprgmr) SERVICE(UPDATE) LOG
DMPAUTH.- UID(authusers) SERVICE(READ)
DMPAUTH.- UID(*) PREVENT

IEAABD.DMPAKEY. access will be restricted to system programming personnel and access will be logged.

Example:
$KEY(IEAABD) TYPE(FAC)
DMPAKEY.- UID(sysprgmr) LOG
DMPAKEY.- UID(*) PREVENT"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25103r504428_chk'
  tag severity: 'medium'
  tag gid: 'V-223430'
  tag rid: 'SV-223430r868783_rule'
  tag stig_id: 'ACF2-ES-000090'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25091r868782_fix'
  tag 'documentable'
  tag legacy: ['SV-106661', 'V-97557']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
