control 'SV-100197' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful attempts to access privileges occur. The SLES for vRealize must generate audit records for all discretionary access control permission modifications using fremovexattr.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'To determine if the system is configured to audit calls to the "fremovexattr" system call, run the following command: 

# auditctl -l | grep syscall | grep fremovexattr

If the system is configured to audit this activity, it will return several lines, such as: 

LIST_RULES: exit,always arch=3221225534 (0xc000003e) syscall=lchown,sethostname,init_module,delete_module,setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr,clock_settime

If no lines are returned, this is a finding.'
  desc 'fix', 'At a minimum, the SLES for vRealize audit system should collect file permission changes for all users and "root". Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b64 -S fremovexattr

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89547'
  tag rid: 'SV-100197r1_rule'
  tag stig_id: 'VRAU-SL-000285'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-96289r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
