control 'SV-206463' do
  title 'The Central Log Server must use multifactor authentication for local access using privileged user accounts.'
  desc 'To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication is defined as: using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network. 

Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to require DoD PKI or another multifactor authentication method for local logon.  

If the Central Log Server is not configured to use multifactor authentication for local access using privileged accounts, this is a finding.'
  desc 'fix', 'This requirement applies to all privileged user accounts used for local logon to the application.

For systems where individual users access, configure and/or manage the system, configure the Central Log Server to use DoD PKI (preferred) or another multifactor authentication solution for local  logon to the Central Log Server.'
  impact 0.5
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6723r285633_chk'
  tag severity: 'medium'
  tag gid: 'V-206463'
  tag rid: 'SV-206463r397444_rule'
  tag stig_id: 'SRG-APP-000151-AU-002330'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-6723r285634_fix'
  tag 'documentable'
  tag legacy: ['SV-96027', 'V-81313']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
