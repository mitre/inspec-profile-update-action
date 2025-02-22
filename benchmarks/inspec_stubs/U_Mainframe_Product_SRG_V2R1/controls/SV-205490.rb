control 'SV-205490' do
  title 'The Mainframe Product must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must use multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication uses two or more factors to achieve authentication. 

Factors include:
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 

A non-privileged account is any information system account with authorizations of a non-privileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Applications integrating with the DoD Active Directory and using the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations.

If the Mainframe Product is configured to require multifactor authentication for network access to non-privileged accounts, this is not a finding'
  desc 'fix', 'Configure the Mainframe Product account management settings to require multifactor authentication for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5756r299703_chk'
  tag severity: 'medium'
  tag gid: 'V-205490'
  tag rid: 'SV-205490r397441_rule'
  tag stig_id: 'SRG-APP-000150-MFP-000211'
  tag gtitle: 'SRG-APP-000150'
  tag fix_id: 'F-5756r299704_fix'
  tag 'documentable'
  tag legacy: ['SV-82829', 'V-68339']
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
