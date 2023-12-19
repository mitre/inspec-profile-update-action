control 'SV-100485' do
  title 'The SLES for vRealize must generate audit records for privileged activities or other system-level access.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'To verify that auditing of privileged command use is configured, run the following command to find relevant setuid programs: 

# find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command: 

# grep path /etc/audit/audit.rules

It should be the case that all relevant setuid programs have a line in the audit rules. 

If it is not the case, this is a finding.'
  desc 'fix', 'At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid programs: 

# find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null

Then, for each setuid program on the system, add a line of the following form to "/etc/audit/audit.rules", where [SETUID_PROG_PATH] is the full path to each setuid program in the list: 

-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -k privileged

OR

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89527r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89835'
  tag rid: 'SV-100485r1_rule'
  tag stig_id: 'VRAU-SL-001410'
  tag gtitle: 'SRG-OS-000471-GPOS-00215'
  tag fix_id: 'F-96577r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
