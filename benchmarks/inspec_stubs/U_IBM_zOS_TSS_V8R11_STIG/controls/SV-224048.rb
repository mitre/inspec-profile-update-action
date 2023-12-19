control 'SV-224048' do
  title 'The IBM z/OS Syslog daemon must be properly defined and secured.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', %q(From the ISPF Command Shell enter:
TSS LIST(SYSLOGD) SEGMENT(OMVS)

If the following guidance is true, this is not a finding.

-The Syslog daemon userid is SYSLOGD.
-The SYSLOGD userid has the STC facility.
-The SYSLOGD userid has UID(0), HOME('/'), and PROGRAM('/bin/sh') specified in the OMVS segment.
-The SYSLOGD started proc is assigned the SYSLOGD userid is in the Started Task Table.

If Syslog daemon is started from /etc/rc then from the ISPF Command Shell enter:
OMVS
cd /etc
cat rc 

If Syslog daemon is started from /etc/rc then ensure that the "_BPX_JOBNAME" and "_BPX_USERID" environment variables are assigned a value of SYSLOGD.

If the Syslog daemon is started from /etc/rc and the "_BPX_JOBNAME" and "_BPX_USERID" environment variables are not assigned a value of SYSLOGD, this is a finding.)
  desc 'fix', "Configure so that the Syslog daemon runs under its own user account. Specifically, it does not share the account defined for the z/OS UNIX kernel.

The Syslog daemon userid is SYSLOGD.
The SYSLOGD userid has the STC facility.
The SYSLOGD userid has UID(0), HOME('/'), and PROGRAM('/bin/sh') specified in the OMVS segment.

To set up and use as an MVS Started Proc, the following sample commands are provided:

TSS CREATE(SYSLOGD) TYPE(USER) NAME(SYSLOGD) -
DEPT(existing-dept) FACILITY(STC) -
PASSWORD(password,0)
TSS ADD(SYSLOGD) DFLTGRP(stctcpx) GROUP(stctcpx)
TSS ADD(SYSLOGD) SOURCE(INTRDR)
TSS ADD(SYSLOGD) UID(0) HOME(/) OMVSPGM(/bin/sh)

The SYSLOGD started proc is assigned the SYSLOGD userid is in the Started Task Table.

TSS ADD(STC) PROCNAME(SYSLOGD) ACID(SYSLOGD)

If /etc/rc is used to start the Syslog daemon, ensure that the _BPX_JOBNAME and _BPX_ USERID environment variables are assigned a value of SYSLOGD."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25721r868999_chk'
  tag severity: 'medium'
  tag gid: 'V-224048'
  tag rid: 'SV-224048r877886_rule'
  tag stig_id: 'TSS0-SL-000030'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25709r869000_fix'
  tag 'documentable'
  tag legacy: ['V-98803', 'SV-107907']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
