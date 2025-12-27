control 'SV-218032' do
  title 'The system package management tool must verify group-ownership on all files and directories associated with the audit package.'
  desc 'Group-ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.'
  desc 'check', "The following command will list which audit files on the system have group-ownership different from what is expected by the RPM database: 

# rpm -V audit | grep '^......G'


If there is output, this is a finding."
  desc 'fix', 'The RPM package management system can restore file group-ownership of the audit package files and directories. The following command will update audit files with group-ownership different from what is expected by the RPM database: 

# rpm --setugids audit'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19513r377111_chk'
  tag severity: 'medium'
  tag gid: 'V-218032'
  tag rid: 'SV-218032r603264_rule'
  tag stig_id: 'RHEL-06-000280'
  tag gtitle: 'SRG-OS-000258'
  tag fix_id: 'F-19511r377112_fix'
  tag 'documentable'
  tag legacy: ['V-38665', 'SV-50466']
  tag cci: ['CCI-001495']
  tag nist: ['AU-9']
end
