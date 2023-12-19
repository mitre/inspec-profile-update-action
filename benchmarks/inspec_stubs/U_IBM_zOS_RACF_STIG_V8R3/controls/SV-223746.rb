control 'SV-223746' do
  title 'IBM z/OS JES2 input sources must be controlled in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer the JES2PARM member of SYS1.PARMLIB.

Review the following resources in the RACF JESINPUT resource class:

INTRDR (internal reader for batch jobs)
nodename (NJE node)
OFFn.* (spool offload receiver)
Rnnnn (RJE workstation)
RDRnn (local card reader)
STCINRDR (internal reader for started tasks)
TSUINRDR (internal reader for TSO logons)

Note: If any of the following are not defined within the JES2 parameters, the resource in the JESINPUT resource class does not have to be defined.

-Nodename is the NAME parameter in the NODE statement. Review the NJE node definitions by searching for NODE( in the report.
-OFFn, where n is the number of the offload receiver. Review the spool offload receiver definitions by searching for OFF( in the report.
-Rnnnn, where nnnn is the number of the remote workstation. Review the RJE node definitions by searching for RMT( in the report.
-RDRnn, where nn is the number of the reader. Review the reader definitions by searching for RDR( in the report.

If the JESINPUT resource class is active, this is not a finding.

If the resources detailed above are protected by generic and/or fully qualified profiles defined to the JESINPUT resource class, this is not a finding.'
  desc 'fix', "Review the following resources in the JESINPUT resource class:

INTRDR (internal reader for batch jobs)
nodename (NJE node)
OFFn.* (spool offload receiver)
Rnnnn (RJE workstation)
RDRnn (local card reader)
STCINRDR (internal reader for started tasks)
TSUINRDR (internal reader for TSO logons)

Note: If any of the following are not defined within the JES2 parameters, the resource in the JESINPUT resource class does not have to be defined.

-Nodename is the NAME parameter in the NODE statement. Review the JES2 parameters for NJE node definitions by searching for NODE( in the report.
-OFFn, where n is the number of the offload receiver. Review the JES2 parameters for spool offload receiver definitions by searching for OFF( in the report.
-Rnnnn, where nnnn is the number of the remote workstation. Review the JES2 parameters for RJE node definitions by searching for RMT( in the report.
-RDRnn, where nn is the number of the reader. Review the JES2 parameters for reader definitions by searching for RDR( in the report.

Define the JESINPUT resource class to the ACTIVE CLASSES in RACF SETROPTS.

Configure the resources detailed above to be protected by generic and/or fully qualified profiles defined to the JESINPUT resource class.

Examples:
setr classact(jesinput) 
setr generic(jesinput) 
rdef jesinput intrdr quack(none) owner(admin) audit(failures(read) success(update)) data('Per SRR PDI ZJES0021') 
pe intrdr cl(jesinput) id(<syspsmpl>)
pe intrdr cl(jesinput) id(*) /* all users */"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25419r514926_chk'
  tag severity: 'medium'
  tag gid: 'V-223746'
  tag rid: 'SV-223746r604139_rule'
  tag stig_id: 'RACF-JS-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25407r514927_fix'
  tag 'documentable'
  tag legacy: ['SV-107303', 'V-98199']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
