control 'SV-242652' do
  title 'The Cisco ISE must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Some authentication implementations can be configured to use cached authenticators.

If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'View the SSP for the required value.

Navigate to Administration >> System >> Admin Access >> Authentication >> Password Policy.

Verify the SSP required value matches the "Password cached for" field.

If the Cisco ISE does not prohibit the use of cached authenticators after an organization-defined time period, this is a finding.'
  desc 'fix', 'Navigate to Administration >> System >> Admin Access >> Authentication >> Password Policy.

Set the "Password cached for" field to the organization-defined value available in the SSP.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45927r714264_chk'
  tag severity: 'medium'
  tag gid: 'V-242652'
  tag rid: 'SV-242652r879773_rule'
  tag stig_id: 'CSCO-NM-000470'
  tag gtitle: 'SRG-APP-000400-NDM-000313'
  tag fix_id: 'F-45884r714265_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
