control 'SV-16730' do
  title 'iSCSI passwords are not compliant with DoD policy.'
  desc 'Storage administrators will protect storage configuration data from unauthorized users by using passwords that are in accordance with the policy in DoDI 8500.2'
  desc 'check', 'Work with the system administrator to determine compliance.  Request the system administrator login to the iSCSI storage device and verify that the password is 14 characters. Review the complexity requirements are met by reviewing the configuration with the system administrator. The complexity requirements are one upper case letter, one lower case letter, one special character, and one number. If the password does not meet these requirements, this is a finding.'
  desc 'fix', 'Configure all iSCSI passwords according to DoD policy.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-15978r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15791'
  tag rid: 'SV-16730r1_rule'
  tag stig_id: 'ESX0090'
  tag gtitle: 'iSCSI passwords are not compliant with DoD policy.'
  tag fix_id: 'F-15733r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
