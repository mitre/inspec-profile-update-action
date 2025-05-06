control 'SV-223597' do
  title 'IBM z/OS DFSMS resources must be protected in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET RESOURCE(FAC)
SET VERBOSE
LIST LIKE(STG-)

If all the following guidance is true, this is not a finding.

The resource rule for FACILITY (FAC) $KEY(STGADMIN) has a default access of PREVENT.

STGADMIN.DPDSRN.olddsname is restricted to System Programmers and all access is logged.

The STGADMIN.IGD.ACTIVATE.CONFIGURATION is restricted to System Programmers and all access is logged.

The STGADMIN.IGG.DEFDEL.UALIAS is restricted to Centralized and Decentralized Security personnel and System Programmers and all access is logged.

The resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE is defined with access of PREVENT.

Note: the resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE can be defined with read access for migration purposes. If it is a detailed migration plan must be documented and filed by the ISSM that determines a definite migration period. All access must be logged. At the completion of migration this resource must be configured with access = PREVENT.

The following resources and prefixes may be available to the end-user.
STGADMIN.ADR.COPY.CNCURRNT
STGADMIN.ADR.COPY.FLASHCPY
STGADMIN.ADR.COPY.TOLERATE.ENQF
STGADMIN.ADR.DUMP.CNCURRNT
STGADMIN.ADR.DUMP.TOLERATE.ENQF
STGADMIN.ADR.RESTORE.TOLERATE.ENQF
STGADMIN.ARC.ENDUSER.
STGADMIN.IGG.ALTER.SMS

The following resource is restricted to Application Production Support Team members, Automated Operations, DASD managers, and System programmers.
STGADMIN.IDC.DCOLLECT

The following resources are restricted to Application Production Support Team members, DASD managers, and System programmers.
STGADMIN.ARC.CANCEL
STGADMIN.ARC.LIST
STGADMIN.ARC.QUERY
STGADMIN.ARC.REPORT
STGADMIN.DMO.CONFIG
STGADMIN.IFG.READVTOC
STGADMIN.IGG.DELGDG.FORCE

The following resource prefixes, at a minimum, are restricted to DASD managers and System programmers.
STGADMIN.ADR
STGADMIN.ANT
STGADMIN.ARC
STGADMIN.DMO
STGADMIN.ICK
STGADMIN.IDC
STGADMIN.IFG
STGADMIN.IGG
STGADMIN.IGWSHCDS

The following Storage Administrator functions prefix is restricted to DASD managers and System programmers and all access is logged.
STGADMIN.ADR.STGADMIN.'
  desc 'fix', "Configure access requirements for SMS Resources as follows. Define the guidelines to ensure the resource type, resources, and/or generic equivalent are followed.

(Note: The resource type, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource type, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

The ACF2 resources are defined with a default access of PREVENT.

Ensure that the following items are in effect:

Ensure that no access is given to the high-level STGADMIN resource.

Example:
$KEY(STGADMIN) TYPE(FAC)
- UID(*) PREVENT

Ensure no access is given to resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE.

Example:
$KEY(STGADMIN) TYPE(FAC)
IGG.STGADMIN.IGG.CATALOG.SECURITY.CHANGE-UID(*) PREVENT
Note: the resource STGADMIN.IGG.CATALOG.SECURITY.CHANGE can be defined with read access for migration purposes. If it is a detailed migration plan must be documented and filed with the ISSM that determines a definite migration period. All access must be logged. At the completion of migration this resource must be configured with access = PREVENT

The STGADMIN.DPDSRN.olddsname is restricted to System Programmers and all access is logged.

Example:
$KEY(STGADMIN) TYPE(FAC)
DPDSRN.- UID(sysprgmr) SERVICE(READ) LOG
DPDSRN.- UID(*) PREVENT

The STGADMIN.IGD.ACTIVATE.CONFIGURATION is restricted to System Programmers and all access is logged.

Example:
$KEY(STGADMIN) TYPE(FAC)
IGD.ACTIVATE.CONFIGURATION UID(sysprgmr) SERVICE(READ) LOG
IGD.ACTIVATE.CONFIGURATION UID(*) PREVENT

The STGADMIN.IGG.DEFDEL.UALIAS is restricted to System Programmers and Security personnel and all access is logged.

Example:
$KEY(STGADMIN) TYPE(FAC)
IGG.DEFDEL.UALIAS UID(seca) SERVICE(READ) LOG
IGG.DEFDEL.UALIAS UID(secd) SERVICE(READ) LOG
IGG.DEFDEL.UALIAS UID(sysprgmr) SERVICE(READ) LOG
IGG.DEFDEL.UALIAS UID(*) PREVENT

The following resources and prefixes may be available to the end-user.

STGADMIN.ADR.COPY.CNCURRNT
STGADMIN.ADR.COPY.FLASHCPY
STGADMIN.ADR.COPY.TOLERATE.ENQF
STGADMIN.ADR.DUMP.CNCURRNT
STGADMIN.ADR.DUMP.TOLERATE.ENQF
STGADMIN.ADR.RESTORE.TOLERATE.ENQF
STGADMIN.ARC.ENDUSER.
STGADMIN.IGG.ALTER.SMS

Example:
$KEY(STGADMIN) TYPE(FAC)
ADR.COPY.CNCURRNT.- UID(endusers) SERVICE(READ)

The following resource is restricted to Application Production Support Team members, Automated Operations, DASD managers, and System programmers.

STGADMIN.IDC.DCOLLECT

Example:
$KEY(STGADMIN) TYPE(FAC)
IDC.DCOLLECT.- UID(apps) SERVICE(READ)
IDC.DCOLLECT.- UID(auto) SERVICE(READ)
IDC.DCOLLECT.- UID(dasb) SERVICE(READ)
IDC.DCOLLECT.- UID(dasd) SERVICE(READ)
IDC.DCOLLECT.- UID(sysprgmr) SERVICE(READ)
IDC.DCOLLECT.- UID(*) PREVENT

The following resources are restricted to Application Production Support Team members, DASD managers, and System programmers.

STGADMIN.ARC.CANCEL
STGADMIN.ARC.LIST
STGADMIN.ARC.QUERY
STGADMIN.ARC.REPORT
STGADMIN.DMO.CONFIG
STGADMIN.IFG.READVTOC
STGADMIN.IGG.DELGDG.FORCE

Example:
$KEY(STGADMIN) TYPE(FAC)
ARC.CANCEL.- UID(apps) SERVICE(READ)
ARC.CANCEL.- UID(dasb) SERVICE(READ)
ARC.CANCEL.- UID(dasd) SERVICE(READ)
ARC.CANCEL.- UID(sysprgmr) SERVICE(READ)
ARC.CANCEL.- UID(*) PREVENT

The following resource prefixes, at a minimum, are restricted to DASD managers and System programmers.

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
$KEY(STGADMIN) TYPE(FAC)
ADR. - UID(dasb) SERVICE(READ)
ADR.- UID(dasd) SERVICE(READ)
ADR.- UID(sysprgmr) SERVICE(READ)
ADR.- UID(*) PREVENT

The following Storage Administrator functions prefix is restricted to DASD managers and System programmers and all access is logged.

STGADMIN.ADR.STGADMIN.

Example:
$KEY(STGADMIN) TYPE(FAC)
ADR.STGADMIN.- UID(dasb) SERVICE(READ) LOG
ADR.STGADMIN.- UID(dasd) SERVICE(READ) LOG
ADR.STGADMIN.- UID(sysprgmr) SERVICE(READ) LOG
ADR.STGADMIN.- UID(*) PREVENT"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25270r504761_chk'
  tag severity: 'medium'
  tag gid: 'V-223597'
  tag rid: 'SV-223597r861189_rule'
  tag stig_id: 'ACF2-SM-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25258r858882_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['SV-107003', 'V-97899']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
