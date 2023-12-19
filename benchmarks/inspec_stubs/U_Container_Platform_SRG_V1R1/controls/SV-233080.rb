control 'SV-233080' do
  title 'The container platform must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To ensure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication.

Factors include: 
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric).

A non-privileged account is any information system account with authorizations of a non-privileged user.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Applications integrating with the DoD Active Directory and utilize the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Review the container platform configuration to determine if the container platform is configured to use multifactor authentication for network access to non-privileged accounts. 

If the container platform does not use multifactor authentication for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'Configure the container platform to use multifactor authentication for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36016r599568_chk'
  tag severity: 'medium'
  tag gid: 'V-233080'
  tag rid: 'SV-233080r599569_rule'
  tag stig_id: 'SRG-APP-000150-CTR-000360'
  tag gtitle: 'SRG-APP-000150'
  tag fix_id: 'F-35984r598877_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
