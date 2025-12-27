control 'SV-219289' do
  title 'The Ubuntu operating system must generate audit records when successful/unsuccessful use of rename system call.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', "Verify the Ubuntu operating system generates audit records when successful/unsuccessful use of rename system call.

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep rename

-a always,exit -F arch=b64 -S rename -F auid>=1000 -F auid!=-1 -k delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=-1 -k delete

If the command does not return lines that match the example or the lines are commented out, this is a finding.

Notes:
For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above."
  desc 'fix', 'Configure the audit system to generate audit events when successful/unsuccessful use of the rename system call.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b64 -S rename -Fauid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S rename -F auid>=1000 -F auid!=4294967295 -k delete

Notes: For 32-bit architectures, only the 32-bit specific entries are required. 
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21014r305195_chk'
  tag severity: 'medium'
  tag gid: 'V-219289'
  tag rid: 'SV-219289r610963_rule'
  tag stig_id: 'UBTU-18-010377'
  tag gtitle: 'SRG-OS-000468-GPOS-00212'
  tag fix_id: 'F-21013r305196_fix'
  tag 'documentable'
  tag legacy: ['SV-109905', 'V-100801']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
