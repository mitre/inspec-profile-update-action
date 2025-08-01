control 'SV-96023' do
  title 'The Central Log Server must use multifactor authentication for network access to non-privileged user accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication uses two or more factors to achieve authentication. 

Factors include:
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 

A non-privileged account is any information system account with authorizations of a non-privileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to require DoD PKI or another multifactor authentication method for logon via the network for all non-privileged accounts.

If the Central Log Server is not configured to use multifactor authentication for network access to non-privileged user accounts, this is a finding.'
  desc 'fix', 'This requirement applies to all non-privileged accounts used for access to the system via network access.

For systems where individual users access, configure and/or manage the system, configure the Central Log Server to use DoD PKI (preferred) or another multifactor authentication solution for network access to logon to the Central Log Server.'
  impact 0.5
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-81011r2_chk'
  tag severity: 'medium'
  tag gid: 'V-81309'
  tag rid: 'SV-96023r1_rule'
  tag stig_id: 'SRG-APP-000150-AU-002320'
  tag gtitle: 'SRG-APP-000150-AU-002320'
  tag fix_id: 'F-88091r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
