control 'SV-218030' do
  title 'The system package management tool must verify permissions on all files and directories associated with the audit package.'
  desc 'Permissions on audit binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.'
  desc 'check', %q(The following command will list which audit files on the system have permissions different from what is expected by the RPM database: 

# rpm -V audit | grep '^.M'

If there is any output, for each file or directory found, compare the RPM-expected permissions with the permissions on the file or directory:

# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" audit | grep  [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by RPM, this is a finding.)
  desc 'fix', 'The RPM package management system can restore file access permissions of the audit package files and directories. The following command will update audit files with permissions different from what is expected by the RPM database: 

# rpm --setperms audit'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19511r377105_chk'
  tag severity: 'medium'
  tag gid: 'V-218030'
  tag rid: 'SV-218030r603264_rule'
  tag stig_id: 'RHEL-06-000278'
  tag gtitle: 'SRG-OS-000256'
  tag fix_id: 'F-19509r377106_fix'
  tag 'documentable'
  tag legacy: ['V-38663', 'SV-50464']
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
