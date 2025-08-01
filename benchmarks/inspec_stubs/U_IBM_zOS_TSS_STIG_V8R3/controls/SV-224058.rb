control 'SV-224058' do
  title 'IBM z/OS TCP/IP resources must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.'
  desc 'check', 'If the following guidance is true, this is not a finding.

-The EZA, EZB, and IST resources of the SERVAUTH resource class are properly owned and/or DEFPROT is specified in the SERVAUTH resource class.
-No access is given to the EZA, EZB, and IST high level resources of the SERVAUTH resource class.
-If the product CSSMTP is on the system, no access is given to EZB.CSSMTP of the SERVAUTH resource class.
-If the product CSSMTP is on the system, EZB.CSSMTP.sysname.writername.JESnode will be specified and made available to the CSSMTP started task and authenticated users that require access to use CSSMTP for e-mail services.
-Authenticated users that require access will be permitted access to the second level of the resources in the SERVAUTH resource class. Examples are the network (NETACCESS), port (PORTACCESS), stack (STACKACCESS), and FTP resources in the SERVAUTH resource class.
-The EZB.STACKACCESS. resource access authorizations restrict access to those started tasks with valid requirements and users with valid FTP access requirements.
-The EZB.FTP.*.*.ACCESS.HFS) resource access authorizations restrict access to FTP users with specific written documentation showing a valid requirement exists to access OMVS files and Directories.'
  desc 'fix', 'Develop a plan of action to implement the required changes. Ensure the following items are in effect for TCP/IP resources.

Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product’s installation guide and can be site specific.

-Ensure that the EZA, EZB, and IST resources of the SERVAUTH resource class are properly owned and/or DEFPROT is specified in the SERVAUTH resource class.
-No access is given to the EZA, EZB, and IST resources of the SERVAUTH resource class.
-If the product CSSMTP is on the system, no access is given to EZB.CSSMTP of the SERVAUTH resource class. EZB.CSSMTP.sysname.writername.JESnode will be specified and made available to the CSSMTP started task and authenticated users that require access to use CSSMTP for e-mail services.
-Only authenticated users that require access are permitted access to the second level of the resources in the SERVAUTH resource class. Examples are the network (NETACCESS), port (PORTACCESS), stack (STACKACCESS), and FTP resources in the SERVAUTH resource class.
-The EZB.STACKACCESS. resource access authorizations restrict access to those started tasks with valid requirements and users with valid FTP access requirements.
-The EZB.FTP.*.*.ACCESS.HFS) resource access authorizations restrict access to FTP users with specific written documentation showing a valid requirement exists to access OMVS files and Directories.

The following commands are provided as a sample for implementing resource controls:

TSS ADD(ADMIN) SERVAUTH(EZB)
or
TSS REPLACE(RDT) RESCLASS(SERVAUTH) ATTR(DEFPROT)

TSS PER(authusers) SERVAUTH(EZB.CSSMTP.sysname.writername.JESnode) ACCESS(READ)
TSS PER(authusers) SERVAUTH(EZB.FTP.) ACCESS(READ)
TSS PER(ftpprofile)SERVAUTH(EZB.FTP.sysname.ftpstc.ACCESS.HFS)ACC(READ)
TSS PER(authusers) SERVAUTH(EZB.NETACCESS.) ACCESS(READ)
TSS PER(authusers) SERVAUTH(EZB.PORTACCESS.) ACCESS(READ)
TSS PER(authusers) SERVAUTH(EZB.STACKACCESS.) ACCESS(READ)
TSS PER(ftpprofile)SERVAUTH(EZB.STACKACCESS.sysname.TCPIP)ACC(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25731r516573_chk'
  tag severity: 'medium'
  tag gid: 'V-224058'
  tag rid: 'SV-224058r561402_rule'
  tag stig_id: 'TSS0-TC-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25719r516574_fix'
  tag 'documentable'
  tag legacy: ['SV-107927', 'V-98823']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
