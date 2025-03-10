control 'SV-240381' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful attempts to access privileges occur. The SLES for vRealize must generate audit records for all discretionary access control permission modifications using fchmod.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'To determine if the system is configured to audit calls to the "fchmod" system call, run the following command: 

# auditctl -l | grep syscall | grep fchmod

If the system is configured to audit this activity, it will return several lines, such as: 

LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid=0 syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat
LIST_RULES: exit,always arch=3221225534 (0xc000003e) auid>=500 (0x1f4) auid!=-1 (0xffffffff) syscall=chmod,fchmod,chown,fchown,fchownat,fchmodat

If no lines are returned, this is a finding.'
  desc 'fix', 'At a minimum, the SLES for vRealize audit system should collect file permission changes for all users and "root". Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b64 -S fchmod -F auid=0
-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43614r670882_chk'
  tag severity: 'medium'
  tag gid: 'V-240381'
  tag rid: 'SV-240381r670884_rule'
  tag stig_id: 'VRAU-SL-000265'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-43573r670883_fix'
  tag 'documentable'
  tag legacy: ['SV-100189', 'V-89539']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
