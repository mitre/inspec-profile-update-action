control 'SV-250661' do
  title 'The system must ensure proper SNMP configuration.'
  desc 'If SNMP is not being used, it must remain disabled. If it is being used, the proper trap destination must be configured. If SNMP is not properly configured, monitoring information can be sent to a malicious host that can then use this information to plan an attack. SNMP must be configured on each ESXi host using Power/v CLI. vSphere PowerCLI is a command line tool used to automate vSphere management. PowerCLI is distributed as a Windows PowerShell snapin, and includes 300+ PowerShell cmdlets and use documentation.'
  desc 'check', 'From the Power/v CLI, run:
"vicfg-snmp.pl --server <server_name> -s" to determine if SNMP is being used. An alternative command option instead of the "-s" is "--show".

If SNMP is not being used and "enabled" = 1, this is a finding. 

If the read-only community name is set to "public", this is a finding. 

If the read-write community name is set to "private", this is a finding.'
  desc 'fix', 'If SNMP is not being used, configure "enabled" = 0. From the Power/v CLI, execute "vicfg-snmp.pl --server <server_name> -D".

If SNMP is being used, ensure the community name is configured:
From the vSphere CLI, type "vicfg-snmp.pl --server hostname --username <username> --password <password> -c <community_name>".

To enable SNMP from the vSphere CLI, type. 
# vicfg-snmp.pl --server <hostname> --username <username> --password <password> --enable'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54096r798980_chk'
  tag severity: 'medium'
  tag gid: 'V-250661'
  tag rid: 'SV-250661r798982_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000144'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54050r798981_fix'
  tag 'documentable'
  tag legacy: ['V-39417', 'SV-51275']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
