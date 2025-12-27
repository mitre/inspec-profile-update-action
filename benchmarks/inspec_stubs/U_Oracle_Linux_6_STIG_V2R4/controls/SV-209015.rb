control 'SV-209015' do
  title 'The system package management tool must verify ownership on all files and directories associated with the audit package.'
  desc 'Ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.'
  desc 'check', "The following command will list which audit files on the system have ownership different from what is expected by the RPM database: 

# rpm -V audit | grep '^.....U'

If there is output, this is a finding."
  desc 'fix', 'The RPM package management system can restore file ownership of the audit package files and directories. The following command will update audit files with ownership different from what is expected by the RPM database: 

# rpm --setugids audit'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9268r357830_chk'
  tag severity: 'medium'
  tag gid: 'V-209015'
  tag rid: 'SV-209015r603263_rule'
  tag stig_id: 'OL6-00-000279'
  tag gtitle: 'SRG-OS-000257'
  tag fix_id: 'F-9268r357831_fix'
  tag 'documentable'
  tag legacy: ['V-50865', 'SV-65071']
  tag cci: ['CCI-001494']
  tag nist: ['AU-9']
end
