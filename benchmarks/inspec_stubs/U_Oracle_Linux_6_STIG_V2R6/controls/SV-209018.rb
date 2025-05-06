control 'SV-209018' do
  title 'There must be no world-writable files on the system.'
  desc 'Data in world-writable files can be modified by any user on the system. In almost all circumstances, files can be configured using a combination of user and group permissions to support whatever legitimate access is needed without the risk caused by world-writable files.'
  desc 'check', 'To find world-writable files, run the following command for each local partition [PART], excluding special filesystems such as /selinux, /proc, or /sys: 

# find [PART] -xdev -type f -perm -002

If there is output, this is a finding.'
  desc 'fix', 'It is generally a good idea to remove global (other) write access to a file when it is discovered. However, check with documentation for specific applications before making changes. Also, monitor for recurring world-writable files, as these may be symptoms of a misconfigured application or user account.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9271r357839_chk'
  tag severity: 'medium'
  tag gid: 'V-209018'
  tag rid: 'SV-209018r793739_rule'
  tag stig_id: 'OL6-00-000282'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9271r357840_fix'
  tag 'documentable'
  tag legacy: ['SV-65077', 'V-50871']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
