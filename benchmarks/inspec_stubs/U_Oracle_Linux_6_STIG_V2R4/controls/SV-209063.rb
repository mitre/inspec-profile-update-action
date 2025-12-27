control 'SV-209063' do
  title 'The system package management tool must verify permissions on all files and directories associated with packages.'
  desc 'Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.'
  desc 'check', %q(The following command will list which files and directories on the system have permissions different from what is expected by the RPM database: 

# rpm -Va  | grep '^.M'

If there is any output, for each file or directory found, find the associated RPM package and compare the RPM-expected permissions with the actual permissions on the file or directory:

# rpm -qf [file or directory name]
# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" [package] | grep  [filename]
# ls -dlL [filename]

If the existing permissions are more permissive than those expected by RPM, this is a finding.)
  desc 'fix', 'The RPM package management system can restore file access permissions of package files and directories. The following command will update permissions on files and directories with permissions different from what is expected by the RPM database: 

# rpm --setperms [package]'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9316r357974_chk'
  tag severity: 'low'
  tag gid: 'V-209063'
  tag rid: 'SV-209063r603263_rule'
  tag stig_id: 'OL6-00-000518'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9316r357975_fix'
  tag 'documentable'
  tag legacy: ['SV-64745', 'V-50539']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
