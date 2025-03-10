control 'SV-223917' do
  title 'IBM z/OS must protect dynamic lists in accordance with proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

'
  desc 'check', 'Refer to the CSV-prefixed resources defined below:

CSVAPF.
CSVAPF.MVS.SETPROG.FORMAT.DYNAMIC
CSVAPF.MVS.SETPROG.FORMAT.STATIC
CSVDYLPA.
CSVDYNEX.
CSVDYNEX.LIST
CSVDYNL.
CSVDYNL.UPDATE.LNKLST
CSVLLA.

If the TSS IBMFAC resource class in the RDT has the DEFPROT attribute specified and/or the CSV resources and/or generic equivalent are owned this is not a finding.

If the TSS resources and/or generic equivalent identified above are defined with ACTION(AUDIT) and UPDATE access restricted to system programming personnel this is not a finding.

If the TSS CSVDYNEX.LIST resource and/or generic equivalent is defined with ACTION(AUDIT) and UPDATE access restricted to system programming personnel this is a finding.

If the TSS CSVDYNEX.LIST resource and/or generic equivalent are defined with READ access restricted to auditors this is not a finding.

If the products CICS and/or CONTROL-O are on the system, and the TSS access to the CSVLLA resource access to the CSVLLA resource and/or generic equivalent are defined with ACTION(AUDIT) and UPDATE access restricted to the CICS and CONTROL-O STC ACIDs this is not a finding.

If any software product requires access to dynamic LPA updates on the system, the TSS access to the CSVDYLPA resource and/or generic equivalent will be defined with ACTION(AUDIT) and UPDATE only after the product has been validated with the appropriate STIG or SRG for compliance AND receives documented and filed authorization that details the need and any accepted risks from the site ISSM or equivalent security authority.

Note: In the above, UPDATE access can be substituted with ALL or CONTROL. Review the permissions in the TSS documentation when specifying UPDATE.'
  desc 'fix', 'Configure TSS to ensure that the Dynamic List resources are defined to the IBMFAC resource class and protected. Only system programmers and a limited number of authorized users and Approved authorized Started Tasks are able to issue these commands. All access is logged.

The required CSV-prefixed Facility Class resources are listed below. These resources or generic equivalents should be defined and permitted as required with only z/OS systems programmers and logging enabled. Minimum required list of CSV-prefixed resources:

CSVAPF.
CSVAPF.MVS.SETPROG.FORMAT.DYNAMIC
CSVAPF.MVS.SETPROG.FORMAT.STATIC
CSVDYLPA.
CSVDYLPA.ADD.
CSVDYLPA.ADD.
CSVDYNEX.
CSVDYNEX.LIST
CSVDYNL.
CSVDYNL.UPDATE.LNKLST
CSVLLA.

If DEFPROT is specified in the IBMFAC RDT the following command examples are not required. To prevent access to these resources, the CSV resources are protected using the following commands.

The following commands are provided for example only:

TSS ADDTO(deptacid) IBMFAC(CSV)
or
TSS ADDTO(deptacid) IBMFAC(CSVAPF)
TSS ADDTO(deptacid) IBMFAC(CSVDYLPA)
TSS ADDTO(deptacid) IBMFAC(CSVDYNEX)
TSS ADDTO(deptacid) IBMFAC(CSVDYNL)
TSS ADDTO(deptacid) IBMFAC(CSVDYLPA)
TSS ADDTO(deptacid) IBMFAC(CSVLLA)

Limit authority to those resources to z/OS systems programmers. Restrict to the absolute minimum number of personnel with ACTION(AUDIT) and UPDATE access.

Sample commands are shown here to accomplish this:

TSS PERMIT(syspsmpl) IBMFAC(CSVAPF.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(syspsmpl) IBMFAC(CSVAPF.MVS.SETPROG) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(syspsmpl) IBMFAC(CSVAPF.MVS.SETPROG.FORMAT) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(syspsmpl) IBMFAC(CSVAPF.MVS.SETPROG.SETPROG.FORMAT.DYNAMIC) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(syspsmpl) IBMFAC(CSVAPF.MVS.SETPROG.SETPROG.FORMAT.STATIC) ACCESS(UPDATE) ACTION(AUDIT)

The CSVDYLPA.ADD resource will be permitted to BMC Mainview, CA 1, and CA Common Services STC ACIDs with ACTION(AUDIT) and UPDATE access.

The CSVDYLPA resource will be permitted to BMC Mainview, CA 1, and CA Common Services STC ACIDs with ACTION(AUDIT) and UPDATE access.

Sample commands are shown here to accomplish one set of resources:

TSS PERMIT(syspsmpl) IBMFAC(CSVDYLPA.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(BMC Mainview STC ACID) IBMFAC(CSVDYLPA.ADD.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(CA 1 STC ACID) IBMFAC(CSVDYLPA.ADD.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(CCS STC ACID) IBMFAC(CSVDYLPA.ADD.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(CA 1 STC ACID) IBMFAC(CSVDYLPA.DELETE.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(CCS STC ACID) IBMFAC(CSVDYLPA.DELETE.) ACCESS(UPDATE) ACTION(AUDIT)

The CSVDYNEX.LIST resource and/or generic equivalent will be defined with ACTION(AUDIT) and UPDATE access restricted to system programming personnel.

The CSVDYNEX.LIST resource and/or generic equivalent will be defined with READ access restricted to auditors.

Sample commands are shown here to accomplish this:

TSS PERMIT(syspsmpl) IBMFAC(CSVDYNEX.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(syspsmpl) IBMFAC(CSVDYNEX.LIST) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(smplsmpl) IBMFAC(CSVDYNEX.LIST) ACCESS(READ) 

The CSVLLA resource will be permitted to CICS and CONTROL-O STC ACIDs with ACTION(AUDIT) and UPDATE access.

Sample commands are shown here to accomplish one set of resources:

TSS PERMIT(syspsmpl) IBMFAC(CSVLLA.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(CICS STC ACIDs) IBMFAC(CSVLLA.) ACCESS(UPDATE) ACTION(AUDIT)
TSS PERMIT(CONTROL-O STC ACID) IBMFAC(CSVLLA.) ACCESS(UPDATE) ACTION(AUDIT)'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25590r516150_chk'
  tag severity: 'high'
  tag gid: 'V-223917'
  tag rid: 'SV-223917r856088_rule'
  tag stig_id: 'TSS0-ES-000440'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25578r516151_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000324-GPOS-00125']
  tag 'documentable'
  tag legacy: ['V-98541', 'SV-107645']
  tag cci: ['CCI-000213', 'CCI-002235']
  tag nist: ['AC-3', 'AC-6 (10)']
end
