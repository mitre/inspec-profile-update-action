control 'SV-91651' do
  title 'The DBN-6300 must use multifactor authentication for local access to privileged accounts.'
  desc 'Multifactor authentication is defined as using two or more factors to achieve authentication.

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). 

To ensure accountability and prevent unauthenticated access, privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network. 

Applications integrating with the DoD Active Directory and utilizing the DoD CAC are examples of compliant multifactor authentication solutions.

This control does not apply to the account of last resort or root account. DoD prohibits local user accounts on the device, except for an account of last resort and (where applicable) a root account.'
  desc 'check', 'Multifactor authentication is managed through the LDAP server. Verify that LDAP (remote authentication) is enabled.

Navigate to Settings >> Initial Configuration >> Authentication. 

Verify that LDAP server information is correctly entered and enabled.

Verify that "Native takes precedence" is disabled.

If LDAP server is not connected, or if "Native takes precedence" is not disabled, this is a finding.'
  desc 'fix', 'Configure the LDAP server to be connected correctly and disable "Native takes precedence".

Navigate to Settings >> Initial Configuration >> Authentication.

Enter the correct LDAP server information and press the "Enable" button.

Press the "Native takes precedence" "Disable" button (if it is not already disabled).'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76581r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76955'
  tag rid: 'SV-91651r1_rule'
  tag stig_id: 'DBNW-DM-000051'
  tag gtitle: 'SRG-APP-000151-NDM-000248'
  tag fix_id: 'F-83651r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
