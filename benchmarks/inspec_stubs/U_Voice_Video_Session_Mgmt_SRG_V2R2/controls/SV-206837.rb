control 'SV-206837' do
  title 'The Voice Video Session Manager must generate session (call) records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information.'
  desc 'Any Voice Video session manager providing too much information in session records risks compromising the data and security of the application and system. The structure and content of session records must be carefully considered by the organization and development team.'
  desc 'check', 'Verify the Voice Video Session Manager generates session records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information.

If the Voice Video Session Manager does not generate session records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to generate session records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7092r364700_chk'
  tag severity: 'medium'
  tag gid: 'V-206837'
  tag rid: 'SV-206837r508661_rule'
  tag stig_id: 'SRG-NET-000273-VVSM-00037'
  tag gtitle: 'SRG-NET-000273'
  tag fix_id: 'F-7092r364701_fix'
  tag 'documentable'
  tag legacy: ['V-62107', 'SV-76597']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
