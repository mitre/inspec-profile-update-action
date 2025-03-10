control 'SV-205489' do
  title 'The Mainframe Product must use multifactor authentication for network access to privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet).'
  desc 'check', 'If the Mainframe Product has no function or capability for user logon, this is not applicable.

If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product is configured to require multifactor authentication for network access to privileged accounts, this is not a finding'
  desc 'fix', 'Configure the Mainframe Product account management settings to require multifactor authentication for network access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5755r299700_chk'
  tag severity: 'medium'
  tag gid: 'V-205489'
  tag rid: 'SV-205489r397438_rule'
  tag stig_id: 'SRG-APP-000149-MFP-000207'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-5755r299701_fix'
  tag 'documentable'
  tag legacy: ['SV-82823', 'V-68333']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
