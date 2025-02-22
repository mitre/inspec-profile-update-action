control 'SV-239127' do
  title 'The Photon operating system must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.

'
  desc 'check', 'At the command line, execute the following command to obtain a list of setuid files:

# find / -xdev -perm -4000 -type f -o -perm -2000 -type f

Execute the following command for each setuid file found in the first command:

# grep <setuid_path> /etc/audit/audit.rules

Replace <setuid_path> with each path found in the first command.

If each <setuid_path> does not have a corresponding line in the audit rules, this is a finding. 

A typical corresponding line will look like the following:

-a always,exit -F path=<setuid_path> -F perm=x -F auid>=1000 -F auid!=-1 -k privileged

Note: This check depends on the auditd service to be in a running state for accurate results. Enabling the auditd service is done as part of a separate control.'
  desc 'fix', 'At the command line, execute the following command to obtain a list of setuid files:

# find / -xdev -perm -4000 -type f -o -perm -2000 -type f

Open /etc/audit/rules.d/audit.STIG.rules with a text editor and add the following line:

Replace <setuid_path> with each path found in the first command.

-a always,exit -F path=<setuid_path> -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged

At the command line, execute the following command:

# /sbin/augenrules --load'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Photon OS'
  tag check_id: 'C-42338r816637_chk'
  tag severity: 'medium'
  tag gid: 'V-239127'
  tag rid: 'SV-239127r856045_rule'
  tag stig_id: 'PHTN-67-000056'
  tag gtitle: 'SRG-OS-000327-GPOS-00127'
  tag fix_id: 'F-42297r816638_fix'
  tag satisfies: ['SRG-OS-000327-GPOS-00127', 'SRG-OS-000471-GPOS-00215']
  tag 'documentable'
  tag cci: ['CCI-000172', 'CCI-002234']
  tag nist: ['AU-12 c', 'AC-6 (9)']
end
