control 'SV-205582' do
  title 'The Mainframe Product must implement privileged access authorization to all information systems and infrastructure components for selected vulnerability scanning activities as defined in the site security plan.'
  desc 'In certain situations, the nature of the vulnerability scanning may be more intrusive, or the information system component that is the subject of the scanning may contain highly sensitive information. Privileged access authorization to selected system components facilitates more thorough vulnerability scanning and also protects the sensitive nature of such scanning.

The vulnerability scanning application must use privileged access authorization for the scanning account.'
  desc 'check', 'If the Mainframe Product has no function or capability to perform vulnerability scanning function this is not applicable.

Examine installation and configuration settings.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

If the Mainframe Product does not restrict privilege access to all information system infrastructure components to appropriate personnel, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to restrict privilege access to all information system infrastructure components to appropriate personnel.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5848r299973_chk'
  tag severity: 'medium'
  tag gid: 'V-205582'
  tag rid: 'SV-205582r400165_rule'
  tag stig_id: 'SRG-APP-000414-MFP-000265'
  tag gtitle: 'SRG-APP-000414'
  tag fix_id: 'F-5848r299974_fix'
  tag 'documentable'
  tag legacy: ['SV-82921', 'V-68431']
  tag cci: ['CCI-001067']
  tag nist: ['RA-5 (5)']
end
