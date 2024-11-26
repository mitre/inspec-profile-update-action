control 'SV-251784' do
  title 'The NSX-T Manager must prohibit the use of cached authenticators after an organization-defined time period.'
  desc 'Some authentication implementations can be configured to use cached authenticators.

If cached authentication information is out-of-date, the validity of the authentication information may be questionable.

The organization-defined time period should be established for each device depending on the nature of the device; for example, a device with just a few administrators in a facility with spotty network connectivity may merit a longer caching time period than a device with many administrators.'
  desc 'check', 'From an NSX-T Manager shell, run the following command(s):

>  get service http | find Session

Expected result:
Session timeout:                  600

If the output does not match the expected result, this is a finding.

From an NSX-T Manager shell, run the following command(s):

>  get cli-timeout

Expected result:
600 seconds

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an NSX-T Manager shell, run the following command(s):

> set service http session-timeout 600
> set cli-timeout 600'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Manager NDM'
  tag check_id: 'C-55244r810353_chk'
  tag severity: 'medium'
  tag gid: 'V-251784'
  tag rid: 'SV-251784r851741_rule'
  tag stig_id: 'TNDM-3X-000076'
  tag gtitle: 'SRG-APP-000400-NDM-000313'
  tag fix_id: 'F-55198r810354_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
