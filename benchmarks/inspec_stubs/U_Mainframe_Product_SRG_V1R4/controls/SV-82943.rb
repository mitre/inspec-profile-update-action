control 'SV-82943' do
  title 'The Mainframe Product must prevent the automatic execution of mobile code in, at a minimum, office applications, browsers, email clients, mobile code run-time environments, and mobile agent systems.'
  desc 'Mobile code can cause damage to the system. It can execute without explicit action from, or notification to, a user. 

Preventing automatic execution of mobile code includes, for example, disabling auto execute features on information system components.

This requirement applies to mobile code-enabled software, which is capable of executing one or more types of mobile code.'
  desc 'check', 'If the Mainframe Product has no function or capability for mobile code use, this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product is not configured to prevent the automatic execution of mobile code in all applications, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to prevent the automatic execution of mobile code in all applications.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68453'
  tag rid: 'SV-82943r1_rule'
  tag stig_id: 'SRG-APP-000210-MFP-000281'
  tag gtitle: 'SRG-APP-000210-MFP-000281'
  tag fix_id: 'F-74569r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
