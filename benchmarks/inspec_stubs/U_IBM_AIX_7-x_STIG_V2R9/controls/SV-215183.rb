control 'SV-215183' do
  title 'All system files, programs, and directories must be owned by a system account.'
  desc 'Restricting permissions will protect the files from unauthorized modification.'
  desc 'check', 'Check the ownership of system files, programs, and directories by running the following command: 
# ls -lLa /etc /bin /usr/bin /usr/lbin /usr/ucb /sbin /usr/sbin 

If any of the system files, programs, or directories are not owned by a system account, this is a finding. 

Note: For this check, the system-provided "ipsec" user is considered to be a system account.'
  desc 'fix', 'Change the owner of public directories to "root" or an application account using the following command: 
# chown root </public/directory> 

Note: Replace "root" with an application user as necessary.'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16381r294000_chk'
  tag severity: 'medium'
  tag gid: 'V-215183'
  tag rid: 'SV-215183r508663_rule'
  tag stig_id: 'AIX7-00-001018'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-16379r294001_fix'
  tag 'documentable'
  tag legacy: ['V-91475', 'SV-101573']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
