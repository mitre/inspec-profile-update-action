control 'SV-223748' do
  title 'IBM z/OS JES2 output devices must be controlled in accordance with the proper security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'Refer the JES2PARM member of SYS1.PARMLIB.

Review the following resources in the RACF WRITER resource class:
JES2.** (backstop profile)
JES2.LOCAL.OFFn.* (spool offload transmitter)
JES2.LOCAL.OFFn.ST (spool offload SYSOUT transmitter)
JES2.LOCAL.OFFn.JT (spool offload job transmitter)
JES2.LOCAL.PRTn (local printer)
JES2.LOCAL.PUNn (local punch)
JES2.NJE.nodename (NJE node)
JES2.RJE.Rnnnn.PRm (remote printer)
JES2.RJE.Rnnnn.PUm (remote punch)

-JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem.
-OFFn, where n is the number of the offload transmitter. Determine the numbers by searching for OFF( in the JES2 parameters.
-PRTn, where n is the number of the local printer. Determine the numbers by searching for PRT( in the JES2 parameters.
-PUNn, where n is the number of the local card punch. Determine the numbers by searching for PUN( in the JES2 parameters.
-Nodename is the NAME parameter value specified on the NODE statement. Review the JES2 parameters for NJE node definitions by searching for NODE( in the report.
-Rnnnn.PRm, where nnnn is the number of the remote workstation and m is the number of the printer. Determine the numbers by searching for .PR in the JES2 parameters.
-Rnnnn.PUm, where nnnn is the number of the remote workstation and m is the number of the punch. Determine the numbers by searching for .PU in the JES2 parameters.

If the WRITER resource class is active, this is not a finding.

If the other resources detailed above are protected by generic and/or fully qualified profiles defined to the WRITER resource class with UACC(NONE), this is not a finding.'
  desc 'fix', "Review the following resources in the WRITER resource class:

JES2.** (backstop profile)
JES2.LOCAL.OFFn.* (spool offload transmitter)
JES2.LOCAL.OFFn.ST (spool offload SYSOUT transmitter)
JES2.LOCAL.OFFn.JT (spool offload job transmitter)
JES2.LOCAL.PRTn (local printer)
JES2.LOCAL.PUNn (local punch)
JES2.NJE.nodename (NJE node)
JES2.RJE.Rnnnn.PRm (remote printer)
JES2.RJE.Rnnnn.PUm (remote punch)

-JES2 is typically the name of the JES2 subsystem. Refer to the SUBSYS report and locate the entry with the description of PRIMARY JOB ENTRY SUBSYSTEM. The SUBSYSTEM NAME of this entry is the name of the JES2 subsystem.
-OFFn, where n is the number of the offload transmitter. Determine the numbers by searching for OFF( in the JES2 parameters.
-PRTn, where n is the number of the local printer. Determine the numbers by searching for PRT( in the JES2 parameters.
-PUNn, where n is the number of the local card punch. Determine the numbers by searching for PUN( in the JES2 parameters.
-Nodename is the NAME parameter value specified on the NODE statement. Review the JES2 parameters for NJE node definitions by searching for NODE( in the report.
-Rnnnn.PRm, where nnnn is the number of the remote workstation and m is the number of the printer. Determine the numbers by searching for .PR in the JES2 parameters.
-Rnnnn.PUm, where nnnn is the number of the remote workstation and m is the number of the punch. Determine the numbers by searching for .PU in the JES2 parameters.

Define the WRITER resource class to the ACTIVE CLASSES in RACF SETROPTS.

Configure the profile JES2.** to have no access in the WRITER resource class.

Configure the resources detailed above to be protected by generic and/or fully qualified profiles defined to the WRITER resource class. 

Examples:
setr classact(writer) 
setr gencmd(writer) generic(writer) 
setr raclist(writer) 
RDEF WRITER JES2.** owner(admin) AUDIT(ALL) UACC(NONE) - 
data('Reference SRR PDI ZJES0031') 
RDEF WRITER JES2.LOCAL.** owner(admin) AUDIT(ALL) UACC(NONE) - 
data('Reference SRR PDI ZJES0031') 
RDEF WRITER JES2.LOCAL.OFF*.JT owner(admin) audit(ALL) UACC(NONE) -
data('Reference SRR PDI ZJES0031') 
RDEF WRITER JES2.LOCAL.OFF*.ST owner(admin) audit(ALL) UACC(NONE) -
data('Reference SRR PDI ZJES0031') 
RDEF WRITER JES2.LOCAL.PRT* owner(admin) audit(ALL) UACC(NONE) - 
data('Reference SRR PDI ZJES0031') 
RDEF WRITER JES2.LOCAL.PUN* owner(admin) audit(ALL) UACC(NONE) - 
data('Reference SRR PDI ZJES0031') 
RDEF WRITER JES2.NJE.** owner(admin) audit(ALL) UACC(NONE) - 
data('Reference SRR PDI ZJES0031') 
RDEF WRITER JES2.RJE.** owner(admin) audit(ALL) UACC(NONE) - 
data('Reference SRR PDI ZJES0031') 

pe JES2.** cl(writer) id(<syspsmpl>) 
pe JES2.LOCAL.** cl(writer) id(<syspsmpl>) 
pe JES2.LOCAL.OFF*.JT cl(writer) id(<syspsmpl>) 
pe JES2.LOCAL.OFF*.ST cl(writer) id(<syspsmpl>) 
pe JES2.LOCAL.PRT* cl(writer) id(<syspsmpl>) 
pe JES2.LOCAL.PUN* cl(writer) id(<syspsmpl>) 
pe JES2.NJE.** cl(writer) id(<syspsmpl>) 
pe JES2.RJE.** cl(writer) id(<syspsmpl>) 
setr racl(writer) Ref"
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25421r514932_chk'
  tag severity: 'medium'
  tag gid: 'V-223748'
  tag rid: 'SV-223748r604139_rule'
  tag stig_id: 'RACF-JS-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25409r514933_fix'
  tag 'documentable'
  tag legacy: ['SV-107307', 'V-98203']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
