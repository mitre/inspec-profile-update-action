control 'SV-215256' do
  title 'AIX audit logs must be rotated daily.'
  desc 'Rotate audit logs daily to preserve audit file system space and to conform to the DoD/DISA requirement. If it is not rotated daily and moved to another location, then there is more of a chance for the compromise of audit data by malicious users.'
  desc 'check', %q(Check for any "crontab" entries that rotate audit logs:

# crontab -l 
30  23  * * * /root/logrotate.sh     #Daily log rotation script
If such a cron job is found, this is not a finding. 

Otherwise, query the SA. 

If there is a process automatically rotating audit logs, this is not a finding. 

If the SA manually rotates audit logs, this is a finding.  

If the audit output is not archived daily, to tape or disk, this is a finding. 

Review the audit log directory.

If more than one file is there, or if the file does not have today's date, this is a finding.)
  desc 'fix', 'Configure a cron job or other automated process to rotate the audit logs on a daily basis.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16454r294219_chk'
  tag severity: 'medium'
  tag gid: 'V-215256'
  tag rid: 'SV-215256r508663_rule'
  tag stig_id: 'AIX7-00-002057'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16452r294220_fix'
  tag 'documentable'
  tag legacy: ['V-91651', 'SV-101749']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
