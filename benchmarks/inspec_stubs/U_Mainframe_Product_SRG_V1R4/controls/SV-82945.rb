control 'SV-82945' do
  title 'The Mainframe Product must prompt the user for action prior to executing mobile code.'
  desc 'Mobile code can cause damage to the system. It can execute without explicit action from, or notification to, a user. 

Actions enforced before executing mobile code include, for example, prompting users prior to opening email attachments and disabling automatic execution.

This requirement applies to mobile code-enabled software, which is capable of executing one or more types of mobile code.'
  desc 'check', 'If the Mainframe Product has no function or capability for mobile code use, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to prompt user for action before executing mobile code, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to prompt the user for action before executing mobile code.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68987r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68455'
  tag rid: 'SV-82945r1_rule'
  tag stig_id: 'SRG-APP-000488-MFP-000282'
  tag gtitle: 'SRG-APP-000488-MFP-000282'
  tag fix_id: 'F-74571r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
