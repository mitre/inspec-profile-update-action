control 'SV-224049' do
  title 'IBM z/OS DFSMS resources must be protected in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'If all SMS resources and/or generic equivalent are properly protected according to the requirements specified and the following guidance is true, this is not a finding.

The TSS resources are owned or DEFPROT is specified for the resource class.

To avoid authorization failures once a base cluster is accessed via a PATH or AIX by a user or application that has authority to the PATH and AIX, but not the base cluster, APAR OA50118 must be applied.

The resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE is defined with access of NONE.
The resource STGADMIN.IGG.CATALOG.SECURITY.BOTH is defined with access of READ.

Note: The resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE can be defined with read access for migration purposes. If it is, a detailed migration plan must be documented and filed by the ISSM that determines a definite migration period. All access must be logged. At the completion of migration, this resource must be configured with access of NONE.

If the resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE and STGADMIN.IGG.CATALOG.SECURITY.BOTH are both defined, ADMIN.IGG.CATALOG.SECURITY.BOTH takes precedence.

STGADMIN.DPDSRN.olddsname is restricted to system programmers and all access is logged.

The STGADMIN.IGD.ACTIVATE.CONFIGURATION is restricted to system programmers and all access is logged.

The STGADMIN.IGG.DEFDEL.UALIAS is restricted to centralized and decentralized security personnel and system programmers and all access is logged.

The following resources and prefixes may be available to the end user.

STGADMIN.ADR.COPY.CNCURRNT
STGADMIN.ADR.COPY.FLASHCPY
STGADMIN.ADR.COPY.TOLERATE.ENQF
STGADMIN.ADR.DUMP.CNCURRNT
STGADMIN.ADR.DUMP.TOLERATE.ENQF
STGADMIN.ADR.RESTORE.TOLERATE.ENQF
STGADMIN.ARC.ENDUSER.
STGADMIN.IGG.ALTER.SMS

The following resource is restricted to Application Production Support Team members, Automated Operations, DASD managers, and system programmers.

STGADMIN.IDC.DCOLLECT

The following resources are restricted to Application Production Support Team members, DASD managers, and system programmers.

STGADMIN.ARC.CANCEL
STGADMIN.ARC.LIST
STGADMIN.ARC.QUERY
STGADMIN.ARC.REPORT
STGADMIN.DMO.CONFIG
STGADMIN.IFG.READVTOC
STGADMIN.IGG.DELGDG.FORCE

The following resource prefixes, at a minimum, are restricted to DASD managers and system programmers.

STGADMIN.ADR
STGADMIN.ANT
STGADMIN.ARC
STGADMIN.DMO
STGADMIN.ICK
STGADMIN.IDC
STGADMIN.IFG
STGADMIN.IGG
STGADMIN.IGWSHCDS

The following Storage Administrator functions prefix is restricted to DASD managers and system programmers and all access is logged.

STGADMIN.ADR.STGADMIN.'
  desc 'fix', "Ensure that the following are properly specified in the ESM.

Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.

Below is listed the access requirements for SMS Resources. Ensure the guidelines for the resources and/or generic equivalent are followed.

The TSS resources are owned and/or DEFPROT is specified for the resource class.

Configure resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE with no access.
Note: The resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE can be defined with read access for migration purposes. If it is, a detailed migration plan must be documented and filed with the ISSM that determines a definite migration period. All access must be logged. At the completion of migration this resource must be configured with access = NONE.

Configure STGADMIN.IGG.CATALOG.SECURITY.BOTH to have READ access for all.

TSS ADD(ADMIN) IBMFAC(STGADMIN)
or
TSS REPLACE(RDT) RESCLASS(IBMFAC) ATTR(DEFPROT)
The STGADMIN.DPDSRN.olddsname is restricted to System Programmers and all access is logged.

Example:
TSS PERMIT(syspsmpl) IBMFAC(STGADMIN.DPDSRN.olddsname) -
ACCESS(READ) ACTION(AUDIT)

The STGADMIN.IGD.ACTIVATE.CONFIGURATION is restricted to system programmers and all access is logged.

Example:
TSS PERMIT(syspsmpl) IBMFAC(STGADMIN.IGD.ACTIVATE.CONFIGURATION) -
ACCESS(READ) ACTION(AUDIT)

The STGADMIN.IGG.DEFDEL.UALIAS is restricted to system programmers and security personnel and all access is logged.

Example:
TSS PERMIT(secasmpl) IBMFAC(STGADMIN.IGG.DEFDEL.UALIAS) -
ACCESS(READ) ACTION(AUDIT)
TSS PERMIT(secdsmpl) IBMFAC(STGADMIN.IGG.DEFDEL.UALIAS) -
ACCESS(READ) ACTION(AUDIT)
TSS PERMIT(syspsmpl) IBMFAC(STGADMIN.IGG.DEFDEL.UALIAS) -
ACCESS(READ) ACTION(AUDIT)

The following resources and prefixes may be available to the end user.

Example:
STGADMIN.ADR.COPY.CNCURRNT
STGADMIN.ADR.COPY.FLASHCPY
STGADMIN.ADR.COPY.TOLERATE.ENQF
STGADMIN.ADR.DUMP.CNCURRNT
STGADMIN.ADR.DUMP.TOLERATE.ENQF
STGADMIN.ADR.RESTORE.TOLERATE.ENQF
STGADMIN.ARC.ENDUSER.
STGADMIN.IGG.ALTER.SMS

Example:
TSS PERMIT(endusers) IBMFAC(STGADMIN.ADR.COPY.CNCURRNT.) -
ACCESS(READ)

The following resource is restricted to Application Production Support Team members, Automated Operations, DASD managers, and system programmers.

STGADMIN.IDC.DCOLLECT

Example:
TSS PERMIT(appssmpl) IBMFAC(STGADMIN.IDC.DCOLLECT) ACCESS(READ)
TSS PERMIT(autosmpl) IBMFAC(STGADMIN.IDC.DCOLLECT) ACCESS(READ)
TSS PERMIT(dasbsmpl) IBMFAC(STGADMIN.IDC.DCOLLECT) ACCESS(READ)
TSS PERMIT(dasdsmpl) IBMFAC(STGADMIN.IDC.DCOLLECT) ACCESS(READ)
TSS PERMIT(syspsmpl) IBMFAC(STGADMIN.IDC.DCOLLECT) ACCESS(READ)

The following resources are restricted to Application Production Support Team members, DASD managers, and system programmers.

Example:
STGADMIN.ARC.CANCEL
STGADMIN.ARC.LIST
STGADMIN.ARC.QUERY
STGADMIN.ARC.REPORT
STGADMIN.DMO.CONFIG
STGADMIN.IFG.READVTOC
STGADMIN.IGG.DELGDG.FORCE

Example:
TSS PERMIT(appssmpl) IBMFAC(STGADMIN.ARC.CANCEL) ACCESS(READ)
TSS PERMIT(dasbsmpl) IBMFAC(STGADMIN.ARC.CANCEL) ACCESS(READ)
TSS PERMIT(dasdsmpl) IBMFAC(STGADMIN.ARC.CANCEL) ACCESS(READ)
TSS PERMIT(syspsmpl) IBMFAC(STGADMIN.ARC.CANCEL) ACCESS(READ)

The following resource prefixes, at a minimum, are restricted to DASD managers and system programmers.

STGADMIN.ADR
STGADMIN.ANT
STGADMIN.ARC
STGADMIN.DMO
STGADMIN.ICK
STGADMIN.IDC
STGADMIN.IFG
STGADMIN.IGG
STGADMIN.IGWSHCDS

Example:

TSS PERMIT(dasbsmpl) IBMFAC(STGADMIN.ADR) ACCESS(READ)
TSS PERMIT(dasdsmpl) IBMFAC(STGADMIN.ADR) ACCESS(READ)
TSS PERMIT(syspsmpl) IBMFAC(STGADMIN.ADR) ACCESS(READ)

The following Storage Administrator functions prefix is restricted to DASD managers and system programmers and all access is logged.

STGADMIN.ADR.STGADMIN.

Example:

TSS PERMIT(dasbsmpl) IBMFAC(STGADMIN.ADR.STGADMIN.) ACCESS(READ) -
ACTION(AUDIT)
TSS PERMIT(dasdsmpl) IBMFAC(STGADMIN.ADR.STGADMIN.) ACCESS(READ) -
ACTION(AUDIT)
TSS PERMIT(syspsmpl) IBMFAC(STGADMIN.ADR.STGADMIN.) ACCESS(READ) -
ACTION(AUDIT)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25722r869002_chk'
  tag severity: 'medium'
  tag gid: 'V-224049'
  tag rid: 'SV-224049r869004_rule'
  tag stig_id: 'TSS0-SM-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25710r869003_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98805', 'SV-107909']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
