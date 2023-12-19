control 'SV-234543' do
  title 'The UEM server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

According to the CNSS 1253, the IA-5(13) control which is tied to this requirement is not defined at the DoD-level. The organization should specify this value based on numerous factors, including the application in question, the data it hosts and the associated exposures/risks.'
  desc 'check', 'Requirement is Not Applicable when the UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server prohibits the use of cached authenticators after an organization-defined time period.

If the UEM server does not prohibit the use of cached authenticators after an organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the UEM server to prohibit the use of cached authenticators after an organization-defined time period.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37728r615986_chk'
  tag severity: 'medium'
  tag gid: 'V-234543'
  tag rid: 'SV-234543r617355_rule'
  tag stig_id: 'SRG-APP-000400-UEM-000271'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-37693r615273_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
