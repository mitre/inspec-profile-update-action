control 'SV-240524' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful attempts to modify privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'To determine if the system is configured to audit calls to the "chmod" system call, run the following command: 

# auditctl -l | grep syscall | grep chmod

If the system is configured to audit this activity, it will return several lines, such as: 

LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid=0 syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat
LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid>=500 (0x1f4) auid!=-1 (0xffffffff) syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat
LIST_RULES: exit,always arch=1073741827 (0x40000003) syscall=chmod,lchown,sethostname,fchmod,fchown,adjtimex,init_module,delete_module,chown,lchown32,fchown32,chown32,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,clock_settime,fchownat,fchmodat

If no lines are returned, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect file permission changes for all users and "root". Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b64 -S chmod -F auid=0
-a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295
-a always,exit -F arch=b32 -S chmod

OR

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43757r671311_chk'
  tag severity: 'medium'
  tag gid: 'V-240524'
  tag rid: 'SV-240524r671313_rule'
  tag stig_id: 'VRAU-SL-001375'
  tag gtitle: 'SRG-OS-000462-GPOS-00206'
  tag fix_id: 'F-43716r671312_fix'
  tag 'documentable'
  tag legacy: ['SV-100475', 'V-89825']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
