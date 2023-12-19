control 'SV-205508' do
  title 'The Mainframe Product must obscure feedback of authentication information during the authentication process to protect the information from possible exploitation/use by unauthorized individuals.'
  desc 'To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism. 

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk. 

Displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine Mainframe Product installation settings; examine user account configurations.

If the Mainframe Product is not configured to obscure feedback of authentication information during the authentication process, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to obscure feedback of authentication information during the authentication process.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5774r299757_chk'
  tag severity: 'medium'
  tag gid: 'V-205508'
  tag rid: 'SV-205508r397603_rule'
  tag stig_id: 'SRG-APP-000178-MFP-000246'
  tag gtitle: 'SRG-APP-000178'
  tag fix_id: 'F-5774r299758_fix'
  tag 'documentable'
  tag legacy: ['SV-82895', 'V-68405']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
