control 'SV-218031' do
  title 'The system package management tool must verify ownership on all files and directories associated with the audit package.'
  desc 'Ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.'
  desc 'check', "The following command will list which audit files on the system have ownership different from what is expected by the RPM database: 

# rpm -V audit | grep '^.....U'


If there is output, this is a finding."
  desc 'fix', 'The RPM package management system can restore file ownership of the audit package files and directories. The following command will update audit files with ownership different from what is expected by the RPM database: 

# rpm --setugids audit'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19512r377108_chk'
  tag severity: 'medium'
  tag gid: 'V-218031'
  tag rid: 'SV-218031r603264_rule'
  tag stig_id: 'RHEL-06-000279'
  tag gtitle: 'SRG-OS-000257'
  tag fix_id: 'F-19510r377109_fix'
  tag 'documentable'
  tag legacy: ['SV-50465', 'V-38664']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
