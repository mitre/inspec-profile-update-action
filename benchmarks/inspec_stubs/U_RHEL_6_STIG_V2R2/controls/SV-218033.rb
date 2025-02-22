control 'SV-218033' do
  title 'The system package management tool must verify contents of all files associated with the audit package.'
  desc 'The hash on important files like audit system executables should match the information given by the RPM database. Audit executables  with erroneous hashes could be a sign of nefarious activity on the system.'
  desc 'check', %q(The following command will list which audit files on the system have file hashes different from what is expected by the RPM database. 

# rpm -V audit | awk '$1 ~ /..5/ && $2 != "c"'


If there is output, this is a finding.)
  desc 'fix', %q(The RPM package management system can check the hashes of audit system package files. Run the following command to list which audit files on the system have hashes that differ from what is expected by the RPM database: 

# rpm -V audit | grep '^..5'

A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories. 

rpm -Uvh [affected_package]

OR 

yum reinstall [affected_package])
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19514r377114_chk'
  tag severity: 'medium'
  tag gid: 'V-218033'
  tag rid: 'SV-218033r603264_rule'
  tag stig_id: 'RHEL-06-000281'
  tag gtitle: 'SRG-OS-000278'
  tag fix_id: 'F-19512r377115_fix'
  tag 'documentable'
  tag legacy: ['SV-50438', 'V-38637']
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
end
