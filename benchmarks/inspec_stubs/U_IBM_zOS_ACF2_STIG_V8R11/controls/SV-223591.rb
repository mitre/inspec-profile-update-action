control 'SV-223591' do
  title 'IBM z/OS Syslog daemon must be started at z/OS initialization.'
  desc 'To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.

Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following: 

1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication; and

2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.'
  desc 'check', 'SYSLOGD may be started from the shell, a cataloged procedure (STC), or the BPXBATCH program. Additionally, other mechanisms (e.g., a job scheduler) may be used to automatically start the Syslog daemon. To thoroughly analyze this requirement you may need to view the OS SYSLOG using SDSF, find the last IPL, and look for the initialization of SYSLOGD.

If the Syslog daemon SYSLOGD is started automatically during the initialization of the z/S/ system, this is not a finding.'
  desc 'fix', 'Review the files used to initialize tasks during system IPL (e.g., /etc/rc, SYS1.PARMLIB, any Job scheduler definitions) to ensure the Syslog daemon is automatically started during z/OS system initialization.

It is important that syslogd be started during the initialization phase of the z/OS system to ensure that significant messages are not lost. As with other z/OS UNIX daemons, there is more than one way to start SYSLOGD. It can be started as a process in the /etc/rc file or as a z/OS started task.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25264r504746_chk'
  tag severity: 'medium'
  tag gid: 'V-223591'
  tag rid: 'SV-223591r533198_rule'
  tag stig_id: 'ACF2-SL-000020'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25252r504747_fix'
  tag 'documentable'
  tag legacy: ['V-97887', 'SV-106991']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
