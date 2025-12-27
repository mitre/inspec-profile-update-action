control 'SV-208825' do
  title 'All system command files must be owned by root.'
  desc 'System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.'
  desc 'check', 'System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

To find system executables that are not owned by "root", run the following command for each directory [DIR] which contains system executables: 

$ find -L [DIR] \\! -user root

If any system executables are found to not be owned by root, this is a finding.'
  desc 'fix', 'System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command: 

# chown root [FILE]'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9078r357455_chk'
  tag severity: 'medium'
  tag gid: 'V-208825'
  tag rid: 'SV-208825r793610_rule'
  tag stig_id: 'OL6-00-000048'
  tag gtitle: 'SRG-OS-000259'
  tag fix_id: 'F-9078r357456_fix'
  tag 'documentable'
  tag legacy: ['V-50789', 'SV-64995']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
