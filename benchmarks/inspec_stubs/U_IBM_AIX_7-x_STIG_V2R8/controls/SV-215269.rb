control 'SV-215269' do
  title 'The inetd.conf file on AIX must be owned by root.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the ownership of "/etc/inetd.conf": 
# ls -al /etc/inetd.conf 

The above command should yield the following output:
-rw-r----- root system 993 Mar 11 07:04 /etc/inetd.conf

If the file is not owned by root, this is a finding.'
  desc 'fix', 'Change the ownership of "/etc/inetd.conf": 
# chown root /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16467r755152_chk'
  tag severity: 'medium'
  tag gid: 'V-215269'
  tag rid: 'SV-215269r755154_rule'
  tag stig_id: 'AIX7-00-002077'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16465r755153_fix'
  tag 'documentable'
  tag legacy: ['V-91587', 'SV-101685']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
