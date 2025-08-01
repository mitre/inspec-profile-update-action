control 'SV-206480' do
  title 'The Central Log Server must map the authenticated identity to the individual user or group account for PKI-based authentication.'
  desc 'Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to map the authenticated identity to the individual user or group account for PKI-based authentication.

If the Central Log Server is not configured to map the authenticated identity to the individual user or group account for PKI-based authentication, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to map the authenticated identity to the individual user or group account for PKI-based authentication.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6740r285684_chk'
  tag severity: 'low'
  tag gid: 'V-206480'
  tag rid: 'SV-206480r397600_rule'
  tag stig_id: 'SRG-APP-000177-AU-002650'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-6740r285685_fix'
  tag 'documentable'
  tag legacy: ['SV-96077', 'V-81363']
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
