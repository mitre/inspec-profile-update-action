control 'SV-82999' do
  title 'The Mainframe Product, upon detection of a potential integrity violation, must initiate one or more of the following actions: generate an audit record, alert the current user, alert personnel or roles as defined in the site security plan, and/or perform other actions as defined in  site security plan.'
  desc 'Without an audit capability, an integrity violation may not be detected. Organizations select response actions based on types of software, specific software, or information for which there are potential integrity violations. The integrity verification application must be configured to perform one or more of following actions: generates an audit record; alerts current user; alerts organization-defined personnel or roles. The organization may define additional actions to be taken.'
  desc 'check', 'If the Mainframe Product has no function or capability for integrity verification, this is not applicable.

Examine installation and configuration settings. 

If the Mainframe Product is not configured to generate an audit record, alert the current user, alert personnel or roles as defined in site security plan, and/or perform other actions as defined in site security plan, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to alert the current user, alert personnel or roles as defined in site security plan, and/or perform other actions as defined in site security plan.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69041r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68509'
  tag rid: 'SV-82999r1_rule'
  tag stig_id: 'SRG-APP-000485-MFP-000384'
  tag gtitle: 'SRG-APP-000485-MFP-000384'
  tag fix_id: 'F-74625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002724']
  tag nist: ['SI-7 (8)']
end
