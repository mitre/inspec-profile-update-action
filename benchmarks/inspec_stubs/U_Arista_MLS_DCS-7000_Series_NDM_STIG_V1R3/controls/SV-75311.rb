control 'SV-75311' do
  title 'The Arista Multilayer Switch must use multifactor authentication for local access to privileged accounts.'
  desc 'Multifactor authentication is defined as: using two or more factors to achieve authentication.

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric).

To assure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network.

Applications integrating with the DoD Active Directory and utilizing the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Determine if the network device uses multifactor authentication for local access to privileged accounts. This requirement may be verified by demonstration or configuration review. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. 

If multifactor authentication is not used for local access to privileged accounts, this is a finding.

Review the device configuration via the "show running-config" command. The line "aaa authentication login console group [server-group] [radius/tacplus] [local]" must be present and must contain, at a minimum, the server group used for authentication, if present, or the term radius or tacplus to indicate all configured radius or tacplus servers, and the term local for local database authentication.'
  desc 'fix', 'Configure the network device or its associated authentication server to use multifactor authentication for local access to privileged accounts.

To configure the local device to authenticate via its authentication server, enter the following command from the configuration mode interface. Replace the bracketed value with the configured server group name or the name of the server type to validate against all configured servers of that type.

switch(config)#aaa authentication login console group [radius] local'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61801r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60855'
  tag rid: 'SV-75311r1_rule'
  tag stig_id: 'AMLS-NM-000220'
  tag gtitle: 'SRG-APP-000151-NDM-000248'
  tag fix_id: 'F-66565r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
