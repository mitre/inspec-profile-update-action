control 'SV-205491' do
  title 'The Mainframe Product must use multifactor authentication for local access to privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, privileged users must use multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication is defined as: using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network. 

Applications integrating with the DoD Active Directory and using the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations.

If the Mainframe Product is configured to require multifactor authentication for local access to privileged accounts, this is not a finding'
  desc 'fix', 'Configure the Mainframe Product account management settings to require multifactor authentication for local access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5757r299706_chk'
  tag severity: 'medium'
  tag gid: 'V-205491'
  tag rid: 'SV-205491r397444_rule'
  tag stig_id: 'SRG-APP-000151-MFP-000212'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-5757r299707_fix'
  tag 'documentable'
  tag legacy: ['SV-83001', 'V-68511']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
