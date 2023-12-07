control 'SV-48278' do
  title 'Application account passwords must be at least 15 characters in length.'
  desc 'Application/service account passwords must be of sufficient length to prevent being easily cracked.  Application/service accounts that are manually managed must have passwords at least 15 characters in length.'
  desc 'check', 'The site must have a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.  If such a policy does not exist or has not been implemented, this is a finding.'
  desc 'fix', 'Establish a site policy that defines the requirements for application/service account length.  Create application/service account passwords that are at least 15 characters in length.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44956r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36661'
  tag rid: 'SV-48278r2_rule'
  tag stig_id: 'WN08-00-000010-01'
  tag gtitle: 'WIN00-000010-01'
  tag fix_id: 'F-41413r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
