control 'SV-224050' do
  title 'IBM z/OS DFSMS Program Resources must be properly defined and protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'Refer to the load modules residing in the following Load libraries to determine program resource definitions:
v SYS1.DGTLLIB for DFSMSdfp/ISMF
v SYS1.DGTLLIB for DFSMSdss/ISMF
v SYS1.DFQLLIB for DFSMShsm

If the installation moves these modules to another load library the installation-defined load library must be used in the program protection.

If the TSS resources are owned or DEFPROT is specified for the resource class, this is not a finding.

If the TSS resource access authorizations restrict access to the appropriate personnel, this is not a finding.'
  desc 'fix', "Configure the following to be properly specified in the ACP.

Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.

Reference the SMS Program Resources as provided by the following libraries:
v SYS1.DGTLLIB for DFSMSdfp/ISMF
v SYS1.DGTLLIB for DFSMSdss/ISMF
v SYS1.DFQLLIB for DFSMShsm

If the installation moves these modules to another load library the installation-defined load library must be used in the program protection.

The TSS resources as designated in the above are owned and/or DEFPROT is specified for the resource class.

The TSS resource access authorizations restrict access to the appropriate personnel as designated in the above.

The following commands are provided as a sample for implementing resource controls:

Example:
TSS ADD(dept-acid) PROGRAM(ACBFUTO2)
TSS PERMIT(smplsmpl) PROGRAM(ACBFUTO2)
TSS PERMIT(dasdsmpl) PROGRAM(ACBFUTO2)
TSS PERMIT(secasmpl) PROGRAM(ACBFUTO2)
TSS PERMIT(syspsmpl) PROGRAM(ACBFUTO2)
TSS PERMIT(tstcsmpl) PROGRAM(ACBFUTO2)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25723r869005_chk'
  tag severity: 'medium'
  tag gid: 'V-224050'
  tag rid: 'SV-224050r877888_rule'
  tag stig_id: 'TSS0-SM-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25711r869006_fix'
  tag 'documentable'
  tag legacy: ['SV-107911', 'V-98807']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
