control 'SV-215253' do
  title 'AIX must allocate audit record storage capacity to store at least one weeks worth of audit records, when audit records are not immediately sent to a central audit record storage facility.'
  desc 'In order to ensure operating systems have a sufficient storage capacity in which to write the audit logs, operating systems need to be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of AIX.'
  desc 'check', 'Check the file system size where the log file resides is greater than the organizationally defined size of audit logs for one week (1GB). 

Find out where the audit log resides: 
# grep trail /etc/security/audit/config 
        trail = /audit/trail

Find out the available space in the file system hosting the audit logs. 

# df /audit/trail
Filesystem    512-blocks      Free %Used    Iused %Iused Mounted on
/dev/hd4         1966080   1792872    9%     3913     2% /

If the "512-blocks" multiplied by "Free" is less than the required size for the audit logs, this is a finding.'
  desc 'fix', 'Increase the size of the file system hosting the audit logs (by 1GB).
# chfs -a size=+1G <root of file system for audit logs>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16451r294210_chk'
  tag severity: 'medium'
  tag gid: 'V-215253'
  tag rid: 'SV-215253r877391_rule'
  tag stig_id: 'AIX7-00-002033'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-16449r294211_fix'
  tag 'documentable'
  tag legacy: ['V-91517', 'SV-101615']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
