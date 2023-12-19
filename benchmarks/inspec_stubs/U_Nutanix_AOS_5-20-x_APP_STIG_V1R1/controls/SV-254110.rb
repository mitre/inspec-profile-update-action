control 'SV-254110' do
  title 'Nutanix AOS must use multifactor authentication for account access.'
  desc 'Multifactor authentication creates a layered defense and makes it more difficult for an unauthorized person to access the application server. If one factor is compromised or broken, the attacker still has at least one more barrier to breach before successfully breaking into the target. Unlike a simple username/password scenario where the attacker could gain access by knowing both the username and password without the user knowing his account was compromised, multifactor authentication adds the requirement that the attacker must have something from the user, such as a token, or to biometrically be the user.

Multifactor authentication is defined as using two or more factors to achieve authentication. 

Factors include: 
(i) Something a user knows (e.g., password/PIN); 
(ii) Something a user has (e.g., cryptographic identification device, token); or 
(iii) Something a user is (e.g., biometric). A CAC or PKI Hardware Token meets this definition.

A privileged account is defined as an information system account with authorizations of a privileged user. These accounts would be capable of accessing the web management interface.

When accessing the application server via a network connection, administrative access to the application server must be PKI Hardware Token enabled.

'
  desc 'check', 'Confirm Nutanix AOS is set to use multifactor authentication.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the Authentication settings.

If CAC authentication is not enabled, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Prism Elements to use CAC authentication.

1. Log in to Prism Elements.
2. Click on the gear icon in the upper right.
3. Navigate to the Authentication settings. 
4. Select the "Configure Service Account" check box, and then complete the following in the indicated fields:
    a. Select the authentication directory that contains the CAC users that to be authenticated. This list includes the directories configured on the Directory List tab.
    b. Service Username: Enter the username in the user name@domain.com format the web console will use to log in to the Active Directory.
    c. Service Password: Enter the password for the service user name.
    d. Click "Enable CAC".'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57595r858123_chk'
  tag severity: 'medium'
  tag gid: 'V-254110'
  tag rid: 'SV-254110r858401_rule'
  tag stig_id: 'NUTX-AP-000280'
  tag gtitle: 'SRG-APP-000149-AS-000102'
  tag fix_id: 'F-57546r858401_fix'
  tag satisfies: ['SRG-APP-000149-AS-000102', 'SRG-APP-000151-AS-000103']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000767']
  tag nist: ['IA-2 (1)', 'IA-2 (3)']
end
