control 'SV-223987' do
  title 'IBM z/OS JES2 input sources must be controlled in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'Refer the JES2PARM member of SYS1.PARMLIB
Review the following resources in the JESINPUT resource class:

NOTE: If any of the following are not defined within the JES2 parameters, the resource in the JESINPUT resource class does not have to be owned.
INTRDR (internal reader for batch jobs)
nodename (NJE node)
OFFn.* (spool offload receiver)
Rnnnn (RJE workstation)
RDRnn (local card reader)
STCINRDR (internal reader for started tasks)
TSUINRDR (internal reader for TSO logons)

Note 1: Nodename is the NAME parameter in the NODE statement. Review the NJE node definitions by searching for "NODE(" in the report.

Note 2: OFFn, where n is the number of the offload receiver. Review the spool offload receiver definitions by searching for "OFF(" in the report.

Note 3: Rnnnn, where nnnn is the number of the remote workstation. Review the RJE node definitions by searching for "RMT(" in the report.

Note 4: RDRnn, where nn is the number of the reader. Review the reader definitions by searching for "RDR(" in the report.

From the ISPF Command Shell enter:

TSS WHOOWNS JESINPUT(*)
If all of the resources above are owned by generic and/or fully qualified entries in the JESINPUT resource class, this is not a finding.

If any of the above resources are not owned, or are owned inappropriately, in the JESINPUT resource class, this is a finding.'
  desc 'fix', 'Review the following resources in the JESINPUT resource class:

INTRDR (internal reader for batch jobs)
nodename (NJE node)
OFFn.* (spool offload receiver)
Rnnnn (RJE workstation)
RDRnn (local card reader)
STCINRDR (internal reader for started tasks)
TSUINRDR (internal reader for TSO logons)

Note: If any of the following are not defined within the JES2 parameters, the resource in the JESINPUT resource class does not have to be defined.

Note 1: Nodename is the NAME parameter in the NODE statement. Review the JES2 parameters for NJE node definitions by searching for "NODE(" in the report.

Note 2: OFFn, where n is the number of the offload receiver. Review the JES2 parameters for spool offload receiver definitions by searching for "OFF(" in the report.

Note 3: Rnnnn, where nnnn is the number of the remote workstation. Review the JES2 parameters for RJE node definitions by searching for "RMT(" in the report.

Note 4: RDRnn, where nn is the number of the reader. Review the JES2 parameters for reader definitions by searching for "RDR(" in the report.

Ensure all of the defined resources above are owned by generic and/or fully qualified entries in the JESINPUT resource class. 

For Example:

The following commands may be used to establish default protection for resources defined to the JESINPUT resource class:

TSS ADDTO(deptacid) JESINPUT(OFFn.)

Grant read access to authorized users for each of the resources defined to the JESINPUT resource class.

The following is an example of granting operators with a profile ACID of jesopracid permission to restore jobs into any SPOOL off load processor after obtaining permission from the ISSO:

TSS PERMIT(jesopracid) JESINPUT(OFF*.) ACCESS(READ) ACTION(AUDIT) 

The resource definition should be generic if all of the resources of the same type have identical access controls (e.g., if all off load receivers are equivalent).'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25660r516360_chk'
  tag severity: 'medium'
  tag gid: 'V-223987'
  tag rid: 'SV-223987r561402_rule'
  tag stig_id: 'TSS0-JS-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25648r516361_fix'
  tag 'documentable'
  tag legacy: ['V-98681', 'SV-107785']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
