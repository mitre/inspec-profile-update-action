control 'SV-223601' do
  title 'IBM z/OS TCP/IP resources must be properly protected.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ACF command screen enter:
SET RESOURCE(SER)
SET VERBOSE
The SERVAUTH resource class is mapped to the standard resource type SER.
LIST LIKE (-)

If no access is given to the EZA, EZB, and IST high level resources of the SERVAUTH resource class, and default access of PREVENT is specified, this is not a finding.

If the product CSSMTP is on the system, no access is given to EZB.CSSMTP of the SERVAUTH resource class, this is not a finding.

If the product CSSMTP is on the system, EZB.CSSMTP.sysname.writername.JESnode will be specified and made available to the CSSMTP started task and authenticated users that require access to use CSSMTP for email services.

Authenticated users that require access will be permitted access to the second level of the resources in the SERVAUTH resource class. Examples are the network (NETACCESS), port (PORTACCESS), stack (STACKACCESS), and FTP resources in the SERVAUTH resource class.

If the EZB.STACKACCESS. resource access authorizations restrict access to those started tasks with valid requirements and users with valid FTP access requirements, this is not a finding.

If the EZB.FTP.*.*.ACCESS.HFS resource access authorizations restrict access to FTP users with specific written documentation showing a valid requirement exists to access OMVS files and Directories, this is not a finding.

If the EZB.INITSTACK.sysname.tcpname resource access authorizations restrict access before policies have been installed, to users authorized by the system security plan requiring access to the TCP/IP stack, this is not a finding.'
  desc 'fix', "Develop a plan of action to implement the required changes. Ensure the following items are in effect for TCP/IP resources.

(Note: The resource class, resources, and/or resource prefixes identified below are examples of a possible installation. The actual resource class, resources, and/or resource prefixes are determined when the product is actually installed on a system through the product's installation guide and can be site specific.)

The SERVAUTH resource class is mapped to the required resource type SER.

Ensure that the EZA, EZB, and IST resources are defined to the SERVAUTH resource class with a default access of PREVENT.

If the product CSSMTP is on the system, no access is given to EZB.CSSMTP of the SERVAUTH resource class. EZB.CSSMTP.sysname.writername.JESnode will be specified and made available to the CSSMTP started task and authenticated users that require access to use CSSMTP for email services.

Only authenticated users that require access are permitted access to the second level of the resources in the SERVAUTH resource class. Examples are the network (NETACCESS), port (PORTACCESS), stack (STACKACCESS), and FTP resources in the SERVAUTH resource class.

The EZB.STACKACCESS. resource access authorizations restrict access to those started tasks with valid requirements and users with valid FTP access requirements.

The EZB.FTP.*.*.ACCESS.HFS) resource access authorizations restrict access to FTP users with specific written documentation showing a valid requirement exists to access OMVS files and Directories.

The EZB.INITSTACK.sysname.tcpname resource access authorizations restrict access to TCP/IP stack before policies have been installed to users authorized by the system security plan.

The following commands are provided as a sample for implementing resource controls:

$KEY(EZB) TYPE(SER)
- UID(*) PREVENT
CSSMTP. - UID(*) PREVENT
CSSMTP.sysname.writername.JESnode UID(authusers) SERVICE(READ) ALLOW
FTP.- UID(authusers) SERVICE(READ) ALLOW
FTP.sysname.ftpstc.ACCESS.HFS UID(ftpprofile) SERVICE(READ) ALLOW
NETACCESS.- UID(authusers) SERVICE(READ) ALLOW
PORTACCESS.- UID(authusers) SERVICE(READ) ALLOW
STACKACCESS.- UID(authusers) SERVICE(READ) ALLOW
STACKACCESS.sysname.TCPIP UID(ftpprofile) SERVICE(READ) ALLOW
INITSTACK.- UID(authusers) SERVICE(READ) ALLOW

COMPILE 'ACF2.MVA.SER(EZB)' STORE

F ACF2,REBUILD(SER)"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25274r811034_chk'
  tag severity: 'medium'
  tag gid: 'V-223601'
  tag rid: 'SV-223601r861182_rule'
  tag stig_id: 'ACF2-TC-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25262r858887_fix'
  tag 'documentable'
  tag legacy: ['V-97907', 'SV-107011']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
