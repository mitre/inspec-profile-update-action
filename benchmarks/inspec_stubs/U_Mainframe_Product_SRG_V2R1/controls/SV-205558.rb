control 'SV-205558' do
  title 'The Mainframe Product must provide an audit reduction capability that supports after-the-fact investigations of security incidents.'
  desc 'If the audit reduction capability does not support after-the-fact investigations, it is difficult to establish, correlate, and investigate the events leading up to an outage or attack, or identify those responses for one. This capability is also required to comply with applicable Federal laws and DoD policies.

Audit reduction capability must support after-the-fact investigations of security incidents either natively or through the use of third-party tools.

This requirement is specific to applications with audit reduction capabilities.'
  desc 'check', 'If the Mainframe Product does not perform audit data management or storage function this is not applicable.

Examine installation and configuration settings.

Verify the Mainframe Product audit reduction capability supports after-the-fact investigations of security incidents. If it does not, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product audit reduction capability to support after-the-fact investigations of security incidents.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5824r299901_chk'
  tag severity: 'medium'
  tag gid: 'V-205558'
  tag rid: 'SV-205558r851322_rule'
  tag stig_id: 'SRG-APP-000365-MFP-000162'
  tag gtitle: 'SRG-APP-000365'
  tag fix_id: 'F-5824r299902_fix'
  tag 'documentable'
  tag legacy: ['SV-82767', 'V-68277']
  tag cci: ['CCI-001877']
  tag nist: ['AU-7 a']
end
