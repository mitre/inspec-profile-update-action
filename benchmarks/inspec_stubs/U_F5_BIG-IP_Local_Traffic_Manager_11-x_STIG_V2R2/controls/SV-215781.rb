control 'SV-215781' do
  title 'The BIG-IP Core implementation providing user authentication intermediary services must be configured to require multifactor authentication for remote access with privileged accounts to virtual servers in such a way that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.'
  desc 'check', 'If the BIG-IP Core does not provide user authentication intermediary services for virtual servers, this is not applicable.

When user authentication intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to require multifactor authentication for remote access with privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an APM access policy to require multifactor authentication for remote access with privileged accounts to virtual servers in such a way that one of the factors is provided by a device separate from the system gaining access.

If the BIG-IP Core does not implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the BIG-IP Core as follows:

Configure a policy in the BIG-IP APM module to require multifactor authentication for remote access with privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.

Apply APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to require multifactor authentication for remote access with privileged accounts to virtual servers in such a way that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16973r291156_chk'
  tag severity: 'medium'
  tag gid: 'V-215781'
  tag rid: 'SV-215781r831469_rule'
  tag stig_id: 'F5BI-LT-000195'
  tag gtitle: 'SRG-NET-000340-ALG-000091'
  tag fix_id: 'F-16971r291157_fix'
  tag 'documentable'
  tag legacy: ['V-60343', 'SV-74773']
  tag cci: ['CCI-001948']
  tag nist: ['IA-2 (11)']
end
