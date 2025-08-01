control 'SV-99101' do
  title 'The SLES for vRealize must generate audit records when successful/unsuccessful attempts to access privileges occur. The SLES for vRealize must generate audit records for all failed attempts to access files and programs.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'To check that the SLES for vRealize audit system collects unauthorized file accesses, run the following commands:

# grep EACCES /etc/audit/audit.rules

-a exit,always -F arch=b64 -S swapon -F exit=-EACCES
-a exit,always -F arch=b64 -S creat -F exit=-EACCES
-a exit,always -F arch=b64 -S open -F exit=-EACCES

# grep EPERM /etc/audit/audit.rules

-a exit,always -F arch=b64 -S swapon -F exit=-EPERM
-a exit,always -F arch=b64 -S creat -F exit=-EPERM
-a exit,always -F arch=b64 -S open -F exit=-EPERM

If either command lacks output, this is a finding.'
  desc 'fix', 'Add the following to "/etc/audit/audit.rules": 

-a exit,always -F arch=b64 -S swapon -F exit=-EACCES
-a exit,always -F arch=b64 -S creat -F exit=-EACCES
-a exit,always -F arch=b64 -S open -F exit=-EACCES

-a exit,always -F arch=b64 -S swapon -F exit=-EPERM
-a exit,always -F arch=b64 -S creat -F exit=-EPERM
-a exit,always -F arch=b64 -S open -F exit=-EPERM

Or run the following command to implement all logging requirements:

# /etc/dodscript.sh'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88143r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88451'
  tag rid: 'SV-99101r1_rule'
  tag stig_id: 'VROM-SL-000320'
  tag gtitle: 'SRG-OS-000064-GPOS-00033'
  tag fix_id: 'F-95193r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
