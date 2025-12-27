control 'SV-224061' do
  title 'IBM z/OS started tasks for the Base TCP/IP component must be defined in accordance with security requirements.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', "Refer to system Proclibs to determine the TCPIP address space(s).

From the ISPF Command Shell enter:
TSS list(<TCPIP STCs>) SEGMENT(OMVS)

For each TCPIP:

If all of the following items are true, this is not a finding.

If any item is untrue, this is a finding.

From the ISPF Command Shell enter
TSS LIST(EZAZSSI) SEGMENT(OMVS)
If EZAZSSI STC has the STC facility, this is not finding.

-Named TCPIP or, in the case of multiple instances, prefixed with TCPIP.
-Has the STC facility. 

-z/OS UNIX attributes: 
UID(0), HOME directory '/', shell program /bin/sh 

Ensure the following items are in effect for the ACID assigned to the EZAZSSI started task: 
-Named EZAZSSI 
-Has the STC facility."
  desc 'fix', "Develop a plan of action to implement the required changes. Ensure the following items are in effect for the ACID(s) assigned to the TCP/IP address space(s): 

1) Named TCPIP or, in the case of multiple instances, prefixed with TCPIP 

2) Has the STC facility

3) z/OS UNIX attributes: UID(0), HOME directory '/', shell program /bin/sh 

Ensure the following items are in effect for the ACID assigned to the EZAZSSI started task: 

1) Named EZAZSSI 

2) Has the STC facility 

For example:

The following commands can be used to create the user accounts and assign the privileges that are required for the TCP/IP address space and the EZAZSSI started task:

TSS CREATE(TCPIP) TYPE(USER) NAME(TCPIP)
DEPT(existing-dept) FACILITY(STC) PASSWORD(password,0)
TSS ADD(TCPIP) DFLTGRP(STCTCPX) GROUP(STCTCPX)
TSS ADD(TCPIP) SOURCE(INTRDR)
TSS ADD(TCPIP) UID(0) HOME(/) OMVSPGM(/bin/sh)
TSS ADD(TCPIP) MASTFAC(TCP)
TSS ADD(STC) PROCNAME(TCPIP) ACID(TCPIP)
TSS PERMIT(TCPIP) IBMFAC(BPX.DAEMON) ACCESS(READ)

TSS CREATE(EZAZSSI) TYPE(USER) NAME(EZAZSSI)
DEPT(existing-dept) FACILITY(STC) PASSWORD(password,0)
TSS ADD(EZAZSSI) DFLTGRP(STCTCPX) GROUP(STCTCPX)
TSS ADD(EZAZSSI) SOURCE(INTRDR)
TSS ADD(EZAZSSI) UID(non-zero) HOME(/) OMVSPGM(/bin/sh)
TSS ADD(EZAZSSI) MASTFAC(TCP)
TSS ADD(STC) PROCNAME(EZAZSSI) ACID(EZAZSSI)"
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25734r869014_chk'
  tag severity: 'medium'
  tag gid: 'V-224061'
  tag rid: 'SV-224061r877901_rule'
  tag stig_id: 'TSS0-TC-000060'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25722r869015_fix'
  tag 'documentable'
  tag legacy: ['V-98829', 'SV-107933']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
