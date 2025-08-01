control 'SV-223818' do
  title 'IBM z/OS DFSMS resources must be protected in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'If all SMS resources and/or generic equivalent are properly protected according to the requirements specified and the following guidance is true, this is not a finding.

The STGADMIN.** profile in the FACILITY resource class has a default access of NONE and no access is granted at this level.

STGADMIN.DPDSRN.olddsname is restricted to system programmers and all access is logged.

The STGADMIN.IGD.ACTIVATE.CONFIGURATION is restricted to system programmers and all access is logged.

The STGADMIN.IGG.DEFDEL.UALIAS is restricted to Centralized and Decentralized Security personnel and system programmers and all access is logged.

The resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE is defined with access of NONE.

Note: The resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE can be defined with read access for migration purposes. If it is a detailed migration plan must be documented and filed by the ISSM that determines a definite migration period. All access must be logged. At the completion of migration this resource must be configured with access = NONE.

The following resources and prefixes may be available to the end user.

STGADMIN.ADR.COPY.CNCURRNT
STGADMIN.ADR.COPY.FLASHCPY
STGADMIN.ADR.COPY.TOLERATE.ENQF
STGADMIN.ADR.DUMP.CNCURRNT
STGADMIN.ADR.DUMP.TOLERATE.ENQF
STGADMIN.ADR.RESTORE.TOLERATE.ENQF
STGADMIN.ARC.ENDUSER.*
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

STGADMIN.ADR.STGADMIN.*'
  desc 'fix', "(Note: The resources and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Below is listed the access requirements for SMS Resources. Configure the resources and/or generic equivalent are followed.

The RACF resources are defined with a default access of NONE.

The RACF resource rules for the resources specify UACC(NONE) and NOWARNING.

Ensure that no access is given to the high-level STGADMIN resource.

Example:
RDEF FACILITY STGADMIN.** OWNER(ADMIN) -
UACC(NONE) AUDIT(ALL(READ))

Ensure no access is given to resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE.*

Example:
RDEF FACILITY STGADMIN.IGG.CATALOG.SECURITY.CHANGE OWNER(ADMIN) -
UACC(NONE) AUDIT(ALL(READ))

The STGADMIN.DPDSRN.olddsname is restricted to system programmers and all access is logged.

Example:
RDEF FACILITY STGADMIN.DPDSRN.olddsname OWNER(ADMIN) -
UACC(NONE) AUDIT(ALL(READ))

PE STGADMIN.DPDSRN.olddsname CL(FACILITY) ID(syspsmpl)

The STGADMIN.IGD.ACTIVATE.CONFIGURATION is restricted to system programmers and all access is logged.

Example:
RDEF FACILITY STGADMIN.IGD.ACTIVATE.CONFIGURATION OWNER(ADMIN) -
UACC(NONE) AUDIT(ALL(READ))

PE STGADMIN.IGD.ACTIVATE.CONFIGURATION CL(FACILITY) ID(syspsmpl)

The STGADMIN.IGG.DEFDEL.UALIAS is restricted to System Programmers and Security personnel and all access is logged.

Example:
RDEF FACILITY STGADMIN.IGG.DEFDEL.UALIAS OWNER(ADMIN) -
UACC(NONE) AUDIT(ALL(READ))

PE STGADMIN.IGG.DEFDEL.UALIAS CL(FACILITY) ID(secasmpl)
PE STGADMIN.IGG.DEFDEL.UALIAS CL(FACILITY) ID(secdsmpl)
PE STGADMIN.IGG.DEFDEL.UALIAS CL(FACILITY) ID(syspsmpl)

The following resources and prefixes may be available to the end user.

STGADMIN.ADR.COPY.CNCURRNT
STGADMIN.ADR.COPY.FLASHCPY
STGADMIN.ADR.COPY.TOLERATE.ENQF
STGADMIN.ADR.DUMP.CNCURRNT
STGADMIN.ADR.DUMP.TOLERATE.ENQF
STGADMIN.ADR.RESTORE.TOLERATE.ENQF
STGADMIN.ARC.ENDUSER.*
STGADMIN.IGG.ALTER.SMS

Example:
RDEF FACILITY STGADMIN.ADR.COPY.CNCURRNT.** OWNER(ADMIN) -
UACC(NONE) AUDIT(FAILURE(READ))

PE STGADMIN.ADR.COPY.CNCURRNT.** CL(FACILITY) ID(endusers)

The following resource is restricted to Application Production Support Team members, Automated Operations, DASD managers, and system programmers.

STGADMIN.IDC.DCOLLECT

Example:
RDEF FACILITY STGADMIN.IDC.DCOLLECT.** OWNER(ADMIN) -
UACC(NONE) AUDIT(FAILURE(READ))

PE STGADMIN.IDC.DCOLLECT.** CL(FACILITY) ID(appssmpl)
PE STGADMIN.IDC.DCOLLECT.** CL(FACILITY) ID(autosmpl)
PE STGADMIN.IDC.DCOLLECT.** CL(FACILITY) ID(dasbsmpl)
PE STGADMIN.IDC.DCOLLECT.** CL(FACILITY) ID(dasdsmpl)
PE STGADMIN.IDC.DCOLLECT.** CL(FACILITY) ID(syspsmpl)

The following resources are restricted to Application Production Support Team members, DASD managers, and system programmers.

STGADMIN.ARC.CANCEL
STGADMIN.ARC.LIST
STGADMIN.ARC.QUERY
STGADMIN.ARC.REPORT
STGADMIN.DMO.CONFIG
STGADMIN.IFG.READVTOC
STGADMIN.IGG.DELGDG.FORCE

Example:
RDEF FACILITY STGADMIN.ARC.CANCEL.** OWNER(ADMIN) -
UACC(NONE) AUDIT(FAILURE(READ))

PE STGADMIN.ARC.CANCEL.** CL(FACILITY) ID(appssmpl)
PE STGADMIN.ARC.CANCEL.** CL(FACILITY) ID(dasbsmpl)
PE STGADMIN.ARC.CANCEL.** CL(FACILITY) ID(dasdsmpl)
PE STGADMIN.ARC.CANCEL.** CL(FACILITY) ID(syspsmpl)

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
RDEF FACILITY STGADMIN.ADR.** OWNER(ADMIN) -
UACC(NONE) AUDIT(FAILURE(READ))

PE STGADMIN.ADR.** CL(FACILITY) ID(dasbsmpl)
PE STGADMIN.ADR.** CL(FACILITY) ID(dasdsmpl)
PE STGADMIN.ADR.** CL(FACILITY) ID(syspsmpl)

The following Storage Administrator functions prefix is restricted to DASD managers and system programmers and all access is logged.

STGADMIN.ADR.STGADMIN.*

Example:
RDEF FACILITY STGADMIN.ADR.STGADMIN.** OWNER(ADMIN) -
UACC(NONE) AUDIT(ALL(READ))

PE STGADMIN.ADR.STGADMIN.** CL(FACILITY) ID(dasbsmpl)
PE STGADMIN.ADR.STGADMIN.** CL(FACILITY) ID(dasdsmpl)
PE STGADMIN.ADR.STGADMIN.** CL(FACILITY) ID(syspsmpl)"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25491r868869_chk'
  tag severity: 'medium'
  tag gid: 'V-223818'
  tag rid: 'SV-223818r868871_rule'
  tag stig_id: 'RACF-SM-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25479r868870_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98343', 'SV-107447']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
