control 'SV-254242' do
  title 'Windows Server 2022 manually managed application account passwords must be at least 15 characters in length.'
  desc 'Application/service account passwords must be of sufficient length to prevent being easily cracked. Application/service accounts that are manually managed must have passwords at least 15 characters in length.'
  desc 'check', 'Determine if manually managed application/service accounts exist. If none exist, this is NA.

Verify the organization has a policy to ensure passwords for manually managed application/service accounts are at least 15 characters in length.

If such a policy does not exist or has not been implemented, this is a finding.'
  desc 'fix', 'Establish a policy that requires application/service account passwords that are manually managed to be at least 15 characters in length. Ensure the policy is enforced.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57727r848540_chk'
  tag severity: 'medium'
  tag gid: 'V-254242'
  tag rid: 'SV-254242r848542_rule'
  tag stig_id: 'WN22-00-000050'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-57678r848541_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
