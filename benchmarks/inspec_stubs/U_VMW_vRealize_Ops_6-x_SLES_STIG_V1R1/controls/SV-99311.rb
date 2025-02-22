control 'SV-99311' do
  title 'The SLES for vRealize must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'To verify that auditing of privileged command use is configured, run the following command to find relevant setuid programs: 

# find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command: 

# grep path /etc/audit/audit.rules

It should be the case that all relevant setuid programs have a line in the audit rules. If it is not the case, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid programs: 

# find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null

Then, for each setuid program on the system, add a line of the following form to "/etc/audit/audit.rules", where [SETUID_PROG_PATH] is the full path to each setuid program in the list: 

-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -k privileged

OR

# /etc/dodscript.sh'
  impact 0.3
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88353r1_chk'
  tag severity: 'low'
  tag gid: 'V-88661'
  tag rid: 'SV-99311r1_rule'
  tag stig_id: 'VROM-SL-001005'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-95403r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
