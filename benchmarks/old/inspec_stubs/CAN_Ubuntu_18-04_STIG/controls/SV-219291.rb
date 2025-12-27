control 'SV-219291' do
  title 'The Ubuntu operating system must generate audit records when loading dynamic kernel modules.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', "Verify the Ubuntu operating system generates an audit record when adding and deleting kernel modules.

Check the currently configured audit rules with the following command:

# sudo auditctl -l | grep -E 'init_module|finit_module' 

-a always,exit -F arch=b32 -S init_module -S finit_module -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -k modules

If the command does not return lines that matches the example or the lines are commented out, this is a finding.

Notes:
For 32-bit architectures, only the 32-bit specific output lines from the commands are required.
The '-k' allows for specifying an arbitrary identifier and the string after it does not need to match the example output above."
  desc 'fix', 'Configure the audit system to generate audit events when adding and deleting kernel modules.

Add or update the following rules in the "/etc/audit/rules.d/stig.rules" file:

-a always,exit -F arch=b32 -S init_module -S finit_module -k modules
-a always,exit -F arch=b64 -S init_module -S finit_module -k modules

Notes: For 32-bit architectures, only the 32-bit specific entries are required. 
The "root" account must be used to view/edit any files in the /etc/audit/rules.d/ directory.

In order to reload the rules file, issue the following command:

# sudo augenrules --load'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21016r569472_chk'
  tag severity: 'medium'
  tag gid: 'V-219291'
  tag rid: 'SV-219291r610963_rule'
  tag stig_id: 'UBTU-18-010379'
  tag gtitle: 'SRG-OS-000471-GPOS-00216'
  tag fix_id: 'F-21015r569473_fix'
  tag 'documentable'
  tag legacy: ['V-100805', 'SV-109909']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
