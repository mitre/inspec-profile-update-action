control 'SRG-NET-000273-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to generate session (call) records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information.'
  desc 'Any Unified Communications Session Manager providing too much information in session records risks compromising the data and security of the application and system. The structure and content of session records must be carefully considered by the organization and development team.'
  desc 'check', 'Verify the Unified Communications Session Manager generates session records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information.

If the Unified Communications Session Manager does not generate session records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to generate session records that provide information necessary for corrective actions without revealing personally identifiable information or sensitive information.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000273-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000273-VVSM-00101'
  tag rid: 'SRG-NET-000273-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000273-VVSM-00101'
  tag gtitle: 'SRG-NET-000273-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000273-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
