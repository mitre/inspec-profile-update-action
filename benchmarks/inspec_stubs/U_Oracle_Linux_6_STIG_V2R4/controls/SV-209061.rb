control 'SV-209061' do
  title 'The system package management tool must verify ownership on all files and directories associated with packages.'
  desc 'Ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.'
  desc 'check', "The following command will list which files on the system have ownership different from what is expected by the RPM database: 

# rpm -Va | grep '^.....U'

If any output is produced, verify that the changes were due to STIG application and have been documented with the ISSO.

If any output has not been documented with the ISSO, this is a finding."
  desc 'fix', 'The RPM package management system can restore ownership of package files and directories. The following command will update files and directories with ownership different from what is expected by the RPM database: 

# rpm -qf [file or directory name]
# rpm --setugids [package]'
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9314r357968_chk'
  tag severity: 'low'
  tag gid: 'V-209061'
  tag rid: 'SV-209061r603263_rule'
  tag stig_id: 'OL6-00-000516'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-9314r357969_fix'
  tag 'documentable'
  tag legacy: ['V-50593', 'SV-64799']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
