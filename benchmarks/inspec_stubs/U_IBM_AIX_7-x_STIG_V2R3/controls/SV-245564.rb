control 'SV-245564' do
  title 'The inetd.conf file on AIX must be group owned by the "system" group.'
  desc "Failure to give ownership of sensitive files or utilities to system groups may provide unauthorized users with the potential to access sensitive information or change the system configuration which could weaken the system's security posture."
  desc 'check', 'Check the group ownership of "/etc/inetd.conf": 
# ls -al /etc/inetd.conf

The above command should yield the following output:
-rw-r----- root system /etc/inetd.conf

If the file is not group owned by system, this is a finding.'
  desc 'fix', 'Change the group ownership of "/etc/inetd.conf": 
# chgrp system /etc/inetd.conf'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-48843r755131_chk'
  tag severity: 'medium'
  tag gid: 'V-245564'
  tag rid: 'SV-245564r755133_rule'
  tag stig_id: 'AIX7-00-002092'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-48798r755132_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
