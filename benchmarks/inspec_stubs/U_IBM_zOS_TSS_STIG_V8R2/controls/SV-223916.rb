control 'SV-223916' do
  title 'CA-TSS must protect memory and privileged program dumps in accordance with proper security requirements.'
  desc 'Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'If the IEAABD. resource and/or generic equivalent is defined with no access and all access logged, this is not a finding.

If the IEAABD.DMPAUTH. resource and/or generic equivalent is defined with READ access limited to authorized users, this is not a finding.

If the IEAABD.DMPAUTH. resource and/or generic equivalent UPDATE or greater access is restricted to only systems personnel and all access is logged, this is not a finding.

If the IEAABD.DMPAKEY resource and/or generic equivalent is defined and all access is restricted to systems personnel and that all access is logged, this is not a finding.'
  desc 'fix', 'Memory and privileged program dump resources are provided via resources in the FACILITY resource class. Ensure that the following are properly specified in the ESM.

(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resources and/or resource prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site specific.)

Below is listed the access requirements for memory and privileged program dump resources. Ensure the guidelines for the resource type, resources, and/or generic equivalent are followed. When protecting the facilities for dumps lists via the FACILITY resource class, ensure that the following items are in effect:

IEAABD.
IEAABD.DMPAUTH.
IEAABD.DMPAKEY.

The RACF resource rules for the resources specify UACC(NONE) and NOWARNING.

Ensure that no access is given to IEAABD. resource.

Example

RDEF FACILITY IEAABD.** UACC(NONE) OWNER(owner group) AUDIT(ALL(READ))

IEAABD.DMPAUTH. READ access is limited to authorized users that have a valid job duties requirement for access. UPDATE access will be restricted to system programming personnel and access will be logged.

Example:

RDEF FACILITY IEAABD.DMPAUTH.** UACC(NONE) OWNER(owner group) AUDIT(ALL(UPDATE))

PERMIT IEAABD.DMPAUTH.** CLASS(FACILITY) ID(authusers) ACCESS(READ)
PERMIT IEAABD.DMPAUTH.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)

IEAABD.DMPAKEY. access will be restricted to system programming personnel and access will be logged.

Example:

RDEF FACILITY IEAABD.DMPAKEY.** UACC(NONE) OWNER(owner group) AUDIT(ALL(READ))

PERMIT IEAABD.DMPAKEY.** CLASS(FACILITY) ID(syspsmpl) ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25589r516147_chk'
  tag severity: 'medium'
  tag gid: 'V-223916'
  tag rid: 'SV-223916r561402_rule'
  tag stig_id: 'TSS0-ES-000430'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25577r516148_fix'
  tag 'documentable'
  tag legacy: ['SV-107643', 'V-98539']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
