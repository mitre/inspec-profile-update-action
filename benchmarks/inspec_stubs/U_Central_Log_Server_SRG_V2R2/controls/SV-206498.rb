control 'SV-206498' do
  title 'The Central Log Server must be configured to perform audit reduction that supports after-the-fact investigations of security incidents.'
  desc 'If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Audit reduction capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools. 

This requirement is specific to applications with audit reduction capabilities.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server performs audit reduction that supports after-the-fact investigations of security incidents.

If the Central Log Server is not configured to perform audit reduction that supports after-the-fact investigations of security incidents, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to perform audit reduction that supports after-the-fact investigations of security incidents.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6758r285735_chk'
  tag severity: 'low'
  tag gid: 'V-206498'
  tag rid: 'SV-206498r855305_rule'
  tag stig_id: 'SRG-APP-000365-AU-000210'
  tag gtitle: 'SRG-APP-000365'
  tag fix_id: 'F-6758r285736_fix'
  tag 'documentable'
  tag legacy: ['SV-95873', 'V-81159']
  tag cci: ['CCI-001877']
  tag nist: ['AU-7 a']
end
