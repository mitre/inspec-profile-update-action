control 'SV-223823' do
  title 'IBM z/OS TCP/IP resources must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
RLIST SERVAUTH * ALL 

If the following guidance is true, this is not a finding.

The EZA, EZB, and IST resources and/or generic equivalent are defined to the SERVAUTH resource class with a UACC(NONE).

No access is given to the EZA, EZB, and IST high level resources of the SERVAUTH resource class.

If the product CSSMTP is on the system, no access is given to EZB.CSSMTP of the SERVAUTH resource class.

If the product CSSMTP is on the system, EZB.CSSMTP.sysname.writername.JESnode will be specified and made available to the CSSMTP started task and authenticated users that require access to use CSSMTP for email services.

Authenticated users that require access will be permitted access to the second level of the resources in the SERVAUTH resource class. Examples are the network (NETACCESS), port (PORTACCESS), stack (STACKACCESS), and FTP resources in the SERVAUTH resource class.

The EZB.STACKACCESS. resource access authorizations restrict access to those started tasks with valid requirements and users with valid FTP access requirements.

The EZB.FTP.*.*.ACCESS.HFS) resource access authorizations restrict access to FTP users with specific written documentation showing a valid requirement exists to access OMVS files and Directories.

The EZB.INITSTACK.sysname.tcpname resource access authorizations restrict access before policies have been installed, to users authorized by the system security plan requiring access to the TCP/IP stack.'
  desc 'fix', "Develop a plan of action to implement the required changes. Ensure the following items are in effect for TCP/IP resources.

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

Ensure that the EZA, EZB, and IST resources and/or generic equivalent are defined to the SERVAUTH resource class with a UACC(NONE).

No access is given to the EZA, EZB, and IST resources of the SERVAUTH resource class.

If the product CSSMTP is on the system, no access is given to EZB.CSSMTP of the SERVAUTH resource class. EZB.CSSMTP.sysname.writername.JESnode will be specified and made available to the CSSMTP started task and authenticated users that require access to use CSSMTP for e-mail services.

Only authenticated users that require access are permitted access to the second level of the resources in the SERVAUTH resource class. Examples are the network (NETACCESS), port (PORTACCESS), stack (STACKACCESS), and FTP resources in the SERVAUTH resource class.

The EZB.STACKACCESS. resource access authorizations restrict access to those started tasks with valid requirements and users with valid FTP access requirements.

The EZB.FTP.*.*.ACCESS.HFS) resource access authorizations restrict access to FTP users with specific written documentation showing a valid requirement exists to access OMVS files and Directories.

The EZB.INITSTACK.sysname.tcpname resource access authorizations restrict access to TCP/IP stack before policies have been installed to users authorized by the system security plan.

The following commands are provided as a sample for implementing resource controls:

RDEF SERVAUTH EZB.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEF SERVAUTH EZB.CSSMTP.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEF SERVAUTH EZB.CSSMTP.sysname.writername.JESnode UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEF SERVAUTH EZB.FTP.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEF SERVAUTH EZB.NETACCESS.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEF SERVAUTH EZB.PORTACCESS.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEF SERVAUTH EZB.STACKACCESS.** UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))
RDEF SERVAUTH EZB.INITSTACK.**  UACC(NONE) OWNER(ADMIN) AUDIT(FAILURE(READ))

PE EZB.CSSMTP.sysname.writername.JESnode CL(SERVAUTH) ID(authusers) ACC(READ)
PE EZB.FTP.** CL(SERVAUTH) ID(authusers) ACC(READ)
PE EZB.FTP.sysname.ftpstc.ACCESS.HFS CL(SERVAUTH) ID(ftpprofile) ACC(READ)
PE EZB.NETACCESS.** CL(SERVAUTH) ID(authusers) ACC(READ)
PE EZB.PORTACCESS.** CL(SERVAUTH) ID(authusers) ACC(READ)
PE EZB.STACKACCESS.** CL(SERVAUTH) ID(authusers) ACC(READ)
PE EZB.STACKACCESS.sysname.TCPIP CL(SERVAUTH) ID(ftpprofile) ACC(READ)

PE EZB.INITSTACK.** CL (SERVAUTH) ID(authusers)  ACC(READ)

The following notes apply to these controls:

- EZB.STACKACCESS.sysname.TCPIP access READ should be limited to only those started tasks that require access to the TCPIP Stack as well as any users approved for FTP Access (inbound and/or outbound). FTP users should not have access to the EZB.FTP.sysname.ftpstc.ACCESS.HFS resource unless specific written justification documenting valid requirement for those FTP users to access USS files and directories via FTP. 

- To be effective in restricting access, the network (EZB.NETACCESS) resource control requires configuration of the NETACCESS statement in the PROFILE.TCPIP file.

- To be effective in restricting access, the port (EZB.PORTACCESS) resource control requires configuration of a PORT or PORTRANGE statement in the PROFILE.TCPIP file. These port definitions within PROFILE.TCPIP must be defined to include SAF keyword and a valid name. 

A list of possible SERVAUTH resources defined to the first two nodes is shown here: (Note that additional resources may be developed with each new release of TCPIP.)

EZA.DCAS.
EZB.BINDDVIPARANGE.
EZB.CIMPROV.
EZB.FRCAACCESS.
EZB.FTP.
EZB.INITSTACK.
EZB.IOCTL.
EZB.IPSECCMD.
EZB.MODDVIPA.
EZB.NETACCESS.
EZB.NETMGMT.
EZB.NETSTAT.
EZB.NSS.
EZB.NSSCERT.
EZB.OSM.
EZB.PAGENT.
EZB.PORTACCESS.
EZB.RPCBIND.
EZB.SOCKOPT.
EZB.SNMPAGENT.
EZB.STACKACCESS.
EZB.TN3270.
IST.NETMGMT."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25496r868874_chk'
  tag severity: 'medium'
  tag gid: 'V-223823'
  tag rid: 'SV-223823r868876_rule'
  tag stig_id: 'RACF-TC-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25484r868875_fix'
  tag 'documentable'
  tag legacy: ['V-98353', 'SV-107457']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
