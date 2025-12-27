control 'SV-83003' do
  title 'The Mainframe Product must use multifactor authentication for local access to non-privileged accounts.'
  desc 'To assure accountability, prevent unauthenticated access, and prevent misuse of the system, non-privileged users must use multifactor authentication for local access. 

Multifactor authentication is defined as: using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

A non-privileged account is defined as an information system account with authorizations of a regular or non-privileged user. 

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network. 

Applications integrating with the DoD Active Directory and using the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product is configured to require multifactor authentication for local access to non-privileged accounts, this is not a finding'
  desc 'fix', 'Configure the Mainframe Product account management settings to require multifactor authentication for local access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-69045r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68513'
  tag rid: 'SV-83003r2_rule'
  tag stig_id: 'SRG-APP-000152-MFP-000213'
  tag gtitle: 'SRG-APP-000152-MFP-000213'
  tag fix_id: 'F-74629r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000768']
  tag nist: ['IA-2 (4)']
end
