control 'SV-202115' do
  title 'The network device must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Some authentication implementations can be configured to use cached authenticators.

If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'Review the network device configuration to determine if the network device or its associated authentication server prohibits the use of cached authenticators after an organization-defined time period.

If cached authenticators are used after an organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the network device or its associated authentication server to prohibit the use of cached authenticators after an organization-defined time period.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2241r381959_chk'
  tag severity: 'medium'
  tag gid: 'V-202115'
  tag rid: 'SV-202115r400123_rule'
  tag stig_id: 'SRG-APP-000400-NDM-000313'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-2242r381960_fix'
  tag 'documentable'
  tag legacy: ['SV-69507', 'V-55261']
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
