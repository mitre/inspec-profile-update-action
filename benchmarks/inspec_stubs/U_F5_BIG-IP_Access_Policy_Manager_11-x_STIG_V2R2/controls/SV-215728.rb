control 'SV-215728' do
  title 'The BIG-IP APM module must be configured to require multifactor authentication for remote access with non-privileged accounts to virtual servers in such a way that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to non-privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD common access card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

An example of compliance with this requirement is the use of a one-time password token and PIN coupled with a password or the use of a CAC/PIV card and PIN coupled with a password.'
  desc 'check', 'If the BIG-IP APM module does not provide user authentication intermediary services, this is not applicable.

Verify the BIG-IP APM module is configured as follows:

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles.

Click "Edit..." in the "Access Policy" column for an Access Profile used for remote access for non-privileged accounts.

Verify the Access Profile is configured to require multifactor authentication for remote access with non-privileged accounts.

If the BIG-IP APM module is not configured to require multifactor authentication for remote access to non-privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure an access policy in the BIG-IP APM module to require multifactor authentication for remote access to non-privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16921r290430_chk'
  tag severity: 'medium'
  tag gid: 'V-215728'
  tag rid: 'SV-215728r831443_rule'
  tag stig_id: 'F5BI-AP-000193'
  tag gtitle: 'SRG-NET-000339-ALG-000090'
  tag fix_id: 'F-16919r290431_fix'
  tag 'documentable'
  tag legacy: ['SV-74477', 'V-60047']
  tag cci: ['CCI-001951']
  tag nist: ['IA-2 (11)']
end
