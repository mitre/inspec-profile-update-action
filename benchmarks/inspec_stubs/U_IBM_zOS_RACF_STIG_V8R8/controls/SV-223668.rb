control 'SV-223668' do
  title 'IBM z/OS must protect dynamic lists in accordance with proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Execute RACF command:
RLIST FACILITY *

If the RACF resources and/or generic equivalent identified below are defined with AUDIT(ALL(READ)) and WRITE or greater access restricted to system programming personnel, this is not a finding.

CSVAPF.
CSVAPF.MVS.SETPROG.FORMAT.DYNAMIC
CSVAPF.MVS.SETPROG.FORMAT.STATIC
CSVDYLPA.
CSVDYNEX.
CSVDYNEX.LIST
CSVDYNL.
CSVDYNL.UPDATE.LNKLST
CSVLLA.

If the RACF CSVDYNEX.LIST resource and/or generic equivalent is defined with AUDIT(FAILURE(READ)SUCCESS(UPDATE)) and WRITE or greater access restricted to system programming personnel, this is not a finding.

If the RACF CSVDYNEX.LIST resource and/or generic equivalent is defined with READ access restricted to auditors, this is not a finding.

If the products CICS and/or CONTROL-O are on the system, the RACF access to the CSVLLA resource and/or generic equivalent will be defined with AUDIT(ALL) and UPDATE access restricted to the CICS and CONTROL-O STC userids.

If any software product requires access to dynamic LPA updates on the system, the RACF access to the CSVDYLPA resource and/or generic equivalent will be defined with LOG and SERVICE(UPDATE) only after the product has been validated with the appropriate STIG or SRG for compliance AND receives documented and filed authorization that details the need and any accepted risks from the site ISSM or equivalent security authority.

Note: In the above, UPDATE access can be substituted with ALTER or CONTROL. Review the permissions in the IBM documentation when specifying UPDATE.'
  desc 'fix', 'Configure the Dynamic List resources to be defined to the RACF FACILITY resource class and protected. Only system programmers and a limited number of authorized users and Approved authorized Started Tasks are able to issue these commands. All access is logged.

The required CSV-prefixed Facility Class resources are listed below. These resources or generic equivalents should be defined and permitted as required with only z/OS systems programmers and logging enabled. Minimum required list of CSV-prefixed resources:

CSVAPF.**
CSVAPF.MVS.SETPROG.FORMAT.DYNAMIC
CSVAPF.MVS.SETPROG.FORMAT.STATIC
CSVDYLPA.**
CSVDYLPA.ADD.**
CSVDYLPA.DELETE.**
CSVDYNEX.**
CSVDYNEX.LIST
CSVDYNL.**
CSVDYNL.UPDATE.LNKLST
CSVLLA.**

Limit authority to those resources to z/OS systems programmers. Restrict to the absolute minimum number of personnel with AUDIT(ALL(READ)) and UPDATE access.

Sample commands are shown here to accomplish this:

RDEF FACILITY CSVAPF.** UACC(NONE) OWNER(syspsmpl) AUDIT(ALL(READ))
RDEF FACILITY CSVAPF.MVS.SETPROG.FORMAT.DYNAMIC.** UACC(NONE) OWNER(syspsmpl) AUDIT(ALL(READ))
RDEF FACILITY CSVAPF.MVS.SETPROG.FORMAT.STATIC.** UACC(NONE) OWNER(syspsmpl) AUDIT(ALL(READ))

PERMIT CSVAPF.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVAPF.MVS.SETPROG.SETPROG.FORMAT.DYNAMIC.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVAPF.MVS.SETPROG.SETPROG.FORMAT.STATIC.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)

The CSVDYLPA.ADD resource will be permitted to products BMC Mainview, CA 1, and CA Common Services STC userids with AUDIT(ALL(READ)) and UPDATE access.

The CSVDYLPA.DELETE resource will be permitted to products CA 1 and CA Common Services STC userids with AUDIT(ALL(READ)) and UPDATE access.

Sample commands are shown here to accomplish one set of resources:

RDEF FACILITY CSVDYLPA.** UACC(NONE) OWNER(syspsmpl) AUDIT(ALL(READ))
RDEF FACILITY CSVDYLPA.ADD.** UACC(NONE) OWNER(syspsmpl) AUDIT(ALL(READ))
RDEF FACILITY CSVDYLPA.DELETE.** UACC(NONE) OWNER(syspsmpl) AUDIT(ALL(READ))

PERMIT CSVDYLPA.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVDYLPA.** CLASS(FACILITY) ID(BMC Mainview STC userid) ACCESS(UPDATE)
PERMIT CSVDYLPA.** CLASS(FACILITY) ID(CA 1 STC userid) ACCESS(UPDATE)
PERMIT CSVDYLPA.** CLASS(FACILITY) ID(CCS STC userid) ACCESS(UPDATE)
PERMIT CSVDYLPA.ADD.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVDYLPA.ADD.** CLASS(FACILITY) ID(BMC Mainview STC userid) ACCESS(UPDATE)
PERMIT CSVDYLPA.ADD.** CLASS(FACILITY) ID(CA 1 STC userid) ACCESS(UPDATE)
PERMIT CSVDYLPA.ADD.** CLASS(FACILITY) ID(CCS STC userid) ACCESS(UPDATE)
PERMIT CSVDYLPA.DELETE.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVDYLPA.DELETE.** CLASS(FACILITY) ID(CA 1 STC userid) ACCESS(UPDATE)
PERMIT CSVDYLPA.DELETE.** CLASS(FACILITY) ID(CCS STC userid) ACCESS(UPDATE)

The CSVDYNEX.LIST resource and/or generic equivalent will be defined with AUDIT(FAILURE(READ)SUCCESS(UPDATE)) and UPDATE access restricted to system programming personnel.

The CSVDYNEX.LIST resource and/or generic equivalent will be defined with READ access restricted to auditors.

Sample commands are shown here to accomplish this:

RDEF FACILITY CSVDYNEX.** UACC(NONE) OWNER(syspsmpl) –
AUDIT(ALL(READ))
RDEF FACILITY CSVDYNEX.LIST.** UACC(NONE) OWNER(syspsmpl) –
AUDIT(FAILURE(READ)SUCCESS(UPDATE))

PERMIT CSVDYNEX.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVDYNEX.LIST.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVDYNEX.LIST.** CLASS(FACILITY) ID(smplsmpl) ACCESS(READ)

The CSVLLA resource will be permitted to CICS and CONTROL-O STC userids with AUDIT(ALL(READ)) and UPDATE access.

Sample commands are shown here to accomplish one set of resources:

RDEF FACILITY CSVLLA.** UACC(NONE) OWNER(syspsmpl) AUDIT(ALL(READ))

PERMIT CSVLLA.** CLASS(FACILITY) ID(syspsmpl) ACCESS(UPDATE)
PERMIT CSVLLA.** CLASS(FACILITY) ID(CICS STC userids) ACCESS(UPDATE)
PERMIT CSVLLA.** CLASS(FACILITY) ID(CONTROL-O STC userid) ACCESS(UPDATE)'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25341r514693_chk'
  tag severity: 'high'
  tag gid: 'V-223668'
  tag rid: 'SV-223668r853574_rule'
  tag stig_id: 'RACF-ES-000200'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25329r514694_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98041', 'SV-107145']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
