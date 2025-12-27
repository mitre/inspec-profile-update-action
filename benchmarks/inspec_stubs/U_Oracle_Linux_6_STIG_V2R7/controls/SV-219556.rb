control 'SV-219556' do
  title 'The audit system must be configured to audit all use of setuid and setgid programs.'
  desc 'Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity.'
  desc 'check', 'To verify that auditing of privileged command use is configured, run the following command once for each local partition [PART] to find relevant setuid / setgid programs:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command:

$ sudo grep path /etc/audit/audit.rules

It should be the case that all relevant setuid / setgid programs have a line in the audit rules. If that is not the case, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid / setgid programs, run the following command for each local partition [PART]:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Then, for each setuid / setgid program on the system, add a line of the following form to "/etc/audit/audit.rules", where [SETUID_PROG_PATH] is the full path to each setuid / setgid program in the list:

-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21281r358208_chk'
  tag severity: 'low'
  tag gid: 'V-219556'
  tag rid: 'SV-219556r854343_rule'
  tag stig_id: 'OL6-00-000198'
  tag gtitle: 'SRG-OS-000327'
  tag fix_id: 'F-21280r358209_fix'
  tag 'documentable'
  tag legacy: ['SV-65351', 'V-51141']
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
