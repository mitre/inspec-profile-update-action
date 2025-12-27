control 'SV-233079' do
  title 'The container platform must use multifactor authentication for network access to privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).'
  desc 'check', 'Review the container platform configuration to determine if the container platform is configured to use multifactor authentication for network access to privileged accounts. 

If the container platform does not use multifactor authentication for network access to privileged accounts, this is a finding.'
  desc 'fix', 'Configure the container platform to use multifactor authentication for network access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36015r601710_chk'
  tag severity: 'medium'
  tag gid: 'V-233079'
  tag rid: 'SV-233079r601711_rule'
  tag stig_id: 'SRG-APP-000149-CTR-000355'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-35983r600725_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
