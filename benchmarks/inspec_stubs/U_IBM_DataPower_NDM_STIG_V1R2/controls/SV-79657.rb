control 'SV-79657' do
  title 'The DataPower Gateway must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Some authentication implementations can be configured to use cached authenticators.

If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'Go to Administration >> Access >> RBM Settings. Click on the Authentication tab. Verify cache mode is set to absolute and set timeout value is set. If it is not, this is a finding.'
  desc 'fix', 'Go to Administration >> Access >> RBM Settings. Click on the Authentication tab. Set cache mode to absolute and set timeout value as needed.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65167'
  tag rid: 'SV-79657r1_rule'
  tag stig_id: 'WSDP-NM-000115'
  tag gtitle: 'SRG-APP-000400-NDM-000313'
  tag fix_id: 'F-71107r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
