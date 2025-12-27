control 'SV-223978' do
  title 'IBM z/OS user exits for the FTP server must not be used without proper approval and documentation.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types), organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services provided by default may not be necessary to support essential organizational operations. Additionally, it is sometimes convenient to provide multiple services from a single component (e.g., VPN and IPS); however, doing so increases risk over limiting the services provided by any one component.

To support the requirements and principles of least functionality, the operating system must support the organizational requirements, providing only essential capabilities and limiting the use of ports, protocols, and/or services to only those required, authorized, and approved to conduct official business or to address authorized quality of life issues.'
  desc 'check', 'Refer to the Data configuration file specified on the SYSFTPD DD statement in the FTP started task JCL.

Refer to the file(s) allocated by the STEPLIB DD statement in the FTP started task JCL.

Refer to the libraries specified in the system Linklist and LPA.

If any FTP Server exits are in use, identify them and validate that they were reviewed for integrity and approved by the site AO.

Refer to the following items are in effect for FTP Server user exits:

The FTCHKCMD, FTCHKIP, FTCHKJES, FTCHKPWD, FTPSMFEX and FTPOSTPR modules are not located in the FTP daemon’s STEPLIB, Linklist, or LPA.

NOTE: The ISPF ISRFIND utility can be used to search the system Linklist and LPA for specific modules.

If both of the above are true, this is not a finding.

If any FTP Server user exits are implemented and the site has not had the site systems programmer verify the exit was securely written and installed, this is a finding.'
  desc 'fix', 'Review the configuration statements in the FTP.DATA file. Review the FTP daemon STEPLIB, system Linklist, and Link Pack Area libraries. If FTP Server exits are enabled or present, and have not been approved by the site ISSM and not securely written and implemented by the site systems programmer, they should not be installed. Verify that none of the following exits are installed unless they have met the requirements listed above:
FTCHKCMD
FTCHKIP
FTCHKJES
FTCHKPWD
FTPOSTPR
FTPSMFEX'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25651r516333_chk'
  tag severity: 'medium'
  tag gid: 'V-223978'
  tag rid: 'SV-223978r561402_rule'
  tag stig_id: 'TSS0-FT-000060'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-25639r516334_fix'
  tag 'documentable'
  tag legacy: ['V-98663', 'SV-107767']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
