control 'SV-205516' do
  title 'The Mainframe Product must prevent the automatic execution of mobile code in, at a minimum, office applications, browsers, email clients, mobile code run-time environments, and mobile agent systems.'
  desc 'Mobile code can cause damage to the system. It can execute without explicit action from, or notification to, a user. 

Preventing automatic execution of mobile code includes, for example, disabling auto execute features on information system components.

This requirement applies to mobile code-enabled software, which is capable of executing one or more types of mobile code.'
  desc 'check', 'If the Mainframe Product has no function or capability for mobile code use, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product is not configured to prevent the automatic execution of mobile code in all applications, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to prevent the automatic execution of mobile code in all applications.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5782r299781_chk'
  tag severity: 'medium'
  tag gid: 'V-205516'
  tag rid: 'SV-205516r397708_rule'
  tag stig_id: 'SRG-APP-000210-MFP-000281'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-5782r299782_fix'
  tag 'documentable'
  tag legacy: ['SV-82943', 'V-68453']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
