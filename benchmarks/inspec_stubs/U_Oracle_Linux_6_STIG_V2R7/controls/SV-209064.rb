control 'SV-209064' do
  title 'The system package management tool must verify contents of all files associated with packages.'
  desc 'The hash on important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system.'
  desc 'check', %q(The following command will list which files on the system have file hashes different from what is expected by the RPM database. 

# rpm -Va | awk '$1 ~ /..5/ && $2 != "c"'

If any output is produced, verify that the changes were due to STIG application and have been documented with the ISSO.

If any output has not been documented with the ISSO, this is a finding.)
  desc 'fix', %q(The RPM package management system can check the hashes of installed software packages, including many that are important to system security. Run the following command to list which files on the system have hashes that differ from what is expected by the RPM database: 

# rpm -Va | grep '^..5'

A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories. 

rpm -Uvh [affected_package]

OR 

yum reinstall [affected_package])
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9317r357977_chk'
  tag severity: 'low'
  tag gid: 'V-209064'
  tag rid: 'SV-209064r793785_rule'
  tag stig_id: 'OL6-00-000519'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9317r357978_fix'
  tag 'documentable'
  tag legacy: ['V-50535', 'SV-64741']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
