control 'SV-223979' do
  title 'The IBM z/OS FTP server daemon must be defined with proper security parameters.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'From the ISPD Command Shell enter:
TSS LIST(FTPD) SEGMENT(OMVS) 
NOTE: The JCL member is typically named FTPD

If the FTPD ACID has the STC facility this is not a finding.

If the FTPD ACID has the following z/OS UNIX attributes this is not a finding.

UID(0), HOME directory ‘/’, shell program /bin/sh.'
  desc 'fix', 'Configure FTP daemon with the following items:

-The FTP daemon is started from a JCL procedure library defined to JES2.

NOTE: The JCL member is typically named FTPD.

-The FTP daemon ACID is FTPD.

-The FTPD ACID has the STC facility.

-The FTPD ACID has the following z/OS UNIX attributes: 
UID(0), HOME directory ‘/’, shell program /bin/sh.

For example:
TSS CREATE(FTPD) TYPE(USER) NAME(FTPD) 
DEPT(existing-dept) FACILITY(STC) PASSWORD(password,0)
TSS ADD(FTPD) DFLTGRP(STCTCPX) GROUP(STCTCPX)
TSS ADD(FTPD) SOURCE(INTRDR)
TSS ADD(FTPD) UID(0) HOME(/) OMVSPGM(/bin/sh)
TSS ADD(FTPD) MASTFAC(TCP)
TSS ADD(STC) PROCNAME(FTPD) ACID(FTPD)
TSS PERMIT(FTPD) IBMFAC(BPX.DAEMON) ACCESS(READ)
TSS PERMIT(FTPD) IBMFAC(BPX.POE) ACCESS(READ)
TSS PERMIT(FTPD) SERVAUTH(EZB.STACKACCESS.)ACCESS(READ)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25652r516336_chk'
  tag severity: 'medium'
  tag gid: 'V-223979'
  tag rid: 'SV-223979r561402_rule'
  tag stig_id: 'TSS0-FT-000070'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25640r516337_fix'
  tag 'documentable'
  tag legacy: ['SV-107769', 'V-98665']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
