control 'SV-246855' do
  title 'The HYCU server must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Some authentication implementations can be configured to use cached authenticators.

If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'Log on to the HYCU VM console and run the following command:
grep Defaults /etc/sudoers

Verify the "Defaults" value is set to "env_reset,timestamp_timeout=0".

If the "Defaults" value is not set to "env_reset,timestamp_timeout=0", this is a finding.'
  desc 'fix', 'Log on to the HYCU VM console and run the following command:
grep Defaults /etc/sudoers

Verify the "Defaults" value is set to "env_reset,timestamp_timeout=0".

If it is not set, run sudo vi /etc/sudoers and configure the timeout value to "0" by adding/editing the following line into the file and saving it:
Defaults  env_reset,timestamp_timeout=0'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50287r768227_chk'
  tag severity: 'medium'
  tag gid: 'V-246855'
  tag rid: 'SV-246855r768229_rule'
  tag stig_id: 'HYCU-IA-000007'
  tag gtitle: 'SRG-APP-000400-NDM-000313'
  tag fix_id: 'F-50241r768228_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
