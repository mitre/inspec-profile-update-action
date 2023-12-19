control 'SV-225247' do
  title 'Policy must require application account passwords be at least 15 characters in length.'
  desc 'Application/service account passwords must be of sufficient length to prevent being easily cracked.  Application/service accounts that are manually managed must have passwords at least 15 characters in length.'
  desc 'check', 'Verify the site has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.  If such a policy does not exist or has not been implemented, this is a finding.'
  desc 'fix', 'Establish a site policy that requires application/service account passwords that are manually managed to be at least 15 characters in length.  Ensure the policy is enforced.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-26946r471083_chk'
  tag severity: 'medium'
  tag gid: 'V-225247'
  tag rid: 'SV-225247r569185_rule'
  tag stig_id: 'WN12-00-000010'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-26934r471084_fix'
  tag 'documentable'
  tag legacy: ['SV-51579', 'V-36661']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
