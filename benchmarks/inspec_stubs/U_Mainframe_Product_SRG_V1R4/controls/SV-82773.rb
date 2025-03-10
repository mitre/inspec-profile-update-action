control 'SV-82773' do
  title 'The Mainframe Product must provide a report generation capability that supports after-the-fact investigations of security incidents.'
  desc 'If the report generation capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

The report generation capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools. 

This requirement is specific to applications with report generation capabilities; however, applications need to support on-demand reporting requirements.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function, this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product report generation capability supports after-the-fact investigations of security incidents. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product report generation capability to support after-the-fact investigations of security incidents.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68283'
  tag rid: 'SV-82773r1_rule'
  tag stig_id: 'SRG-APP-000368-MFP-000165'
  tag gtitle: 'SRG-APP-000368-MFP-000165'
  tag fix_id: 'F-74397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001880']
  tag nist: ['AU-7 a']
end
