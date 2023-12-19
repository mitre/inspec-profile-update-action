control 'SV-206501' do
  title 'The Central Log Server must be configured to generate reports that support after-the-fact investigations of security incidents.'
  desc 'If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

The report generation capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand reporting requirements.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server generates reports that support after-the-fact investigations of security incidents.

If the Central Log Server is not configured to generate reports that support after-the-fact investigations of security incidents, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to generate reports that support after-the-fact investigations of security incidents.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6761r285744_chk'
  tag severity: 'low'
  tag gid: 'V-206501'
  tag rid: 'SV-206501r855308_rule'
  tag stig_id: 'SRG-APP-000368-AU-000240'
  tag gtitle: 'SRG-APP-000368'
  tag fix_id: 'F-6761r285745_fix'
  tag 'documentable'
  tag legacy: ['SV-95879', 'V-81165']
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
