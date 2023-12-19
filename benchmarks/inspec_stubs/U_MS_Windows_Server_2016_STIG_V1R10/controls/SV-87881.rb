control 'SV-87881' do
  title 'Manually managed application account passwords must be at least 15 characters in length.'
  desc 'Application/service account passwords must be of sufficient length to prevent being easily cracked. Application/service accounts that are manually managed must have passwords at least 15 characters in length.'
  desc 'check', 'Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.

If such a policy does not exist or has not been implemented, this is a finding.'
  desc 'fix', 'Establish a policy that requires application/service account passwords that are manually managed to be at least 15 characters in length. Ensure the policy is enforced.'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73333r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73229'
  tag rid: 'SV-87881r1_rule'
  tag stig_id: 'WN16-00-000060'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-79673r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
