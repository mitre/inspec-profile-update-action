control 'SV-225230' do
  title 'The .NET CLR must be configured to use FIPS approved encryption modules.'
  desc '<0> [object Object]'
  desc 'check', 'Examine the .NET CLR configuration files from the vulnerability discussion to find the runtime element and then the "enforceFIPSPolicy" element.

Example:
<configuration> 
  <runtime> 
                <enforceFIPSPolicy enabled="true|false" />
  </runtime>
</configuration>

By default, the .NET "enforceFIPSPolicy" element is set to "true".

If the "enforceFIPSPolicy" element does not exist within the "runtime" element of the CLR configuration, this is not a finding.

If the "enforceFIPSPolicy" element exists and is set to "false", and the IAO has not accepted the risk and documented the risk acceptance, this is a finding.'
  desc 'fix', 'Examine the .NET CLR configuration files to find the runtime element and then the "enforceFIPSPolicy" element.

Example:
<configuration> 
  <runtime> 
                <enforceFIPSPolicy enabled="true|false" />
  </runtime>
</configuration>

Delete the "enforceFIPSPolicy" runtime element, change the setting to "true" or there must be documented IAO approvals for the FIPS setting.'
  impact 0.5
  ref 'DPMS Target Microsoft DotNet Framework 4-0'
  tag check_id: 'C-26929r468005_chk'
  tag severity: 'medium'
  tag gid: 'V-225230'
  tag rid: 'SV-225230r615940_rule'
  tag stig_id: 'APPNET0062'
  tag gtitle: 'SRG-APP-000635'
  tag fix_id: 'F-26917r468006_fix'
  tag legacy: ['SV-40966', 'V-30926']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
