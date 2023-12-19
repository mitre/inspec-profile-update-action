control 'SV-223742' do
  title 'The IBM z/OS FTP server daemon must be defined with proper security parameters.'
  desc 'The FTP Server daemon requires special privileges and access to sensitive resources to provide its system services. Failure to properly define and control the FTP Server daemon could lead to unauthorized access. This exposure may result in the compromise of the integrity and availability of the operating system environment, ACP, and customer data.'
  desc 'check', "From z/OS command screen enter: 
ListUser FTPD OMVS (FTPD is usual name of the FTP daemon)

If all of the following are true, this is not a finding.

If either of the following is untrue, this is a finding.

-The FTPD userid is defined as a PROTECTED userid.
-The FTPD userid has the following z/OS UNIX attributes: UID(0), HOME directory '/', shell program /bin/sh.

From z/OS command screen enter:
RList STARTED FTPD

If a matching entry in the STARTED resource class exists enabling the use of the standard userid and appropriate group, this is not a finding."
  desc 'fix', "Define the FTP daemon userid and a matching entry in the STARTED resource class enabling the use of the standard userid and an appropriate group. 

Define the FTPD userid as a PROTECTED userid. 

Define the FTPD userid with the following z/OS UNIX attributes: UID(0), HOME directory '/', shell program /bin/sh. 

Sample commands to accomplish these requirements are shown here:
Add the FTPD userid:

AU FTPD NAME('STC, FTP Daemon') NOPASSWORD NOOIDCARD DFLTGRP(STCTCPX) OWNER(STCTCPX) OMVS(UID(0) HOME('/') PROGRAM('/bin/sh'))

RDEF STARTED FTPD.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) STDATA(USER(=MEMBER) GROUP(STCTCPX) TRACE(YES))

Additional permissions may be required. See SYS1.TCPIP.SEZAINST(EZARACF) or IBM Comm Server: IP Config Guide."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25415r868831_chk'
  tag severity: 'medium'
  tag gid: 'V-223742'
  tag rid: 'SV-223742r868833_rule'
  tag stig_id: 'RACF-FT-000100'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25403r868832_fix'
  tag 'documentable'
  tag legacy: ['V-98191', 'SV-107295']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
