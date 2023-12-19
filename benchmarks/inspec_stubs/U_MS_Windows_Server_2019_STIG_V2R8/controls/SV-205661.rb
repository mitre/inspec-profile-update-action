control 'SV-205661' do
  title 'Windows Server 2019 manually managed application account passwords must be at least 15 characters in length.'
  desc 'Application/service account passwords must be of sufficient length to prevent being easily cracked. Application/service accounts that are manually managed must have passwords at least 15 characters in length.'
  desc 'check', 'Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.

If such a policy does not exist or has not been implemented, this is a finding.'
  desc 'fix', 'Establish a policy that requires application/service account passwords that are manually managed to be at least 15 characters in length. Ensure the policy is enforced.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5926r354901_chk'
  tag severity: 'medium'
  tag gid: 'V-205661'
  tag rid: 'SV-205661r569188_rule'
  tag stig_id: 'WN19-00-000050'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-5926r354902_fix'
  tag 'documentable'
  tag legacy: ['SV-103547', 'V-93461']
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
