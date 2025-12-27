control 'SV-243134' do
  title 'The password configured on the WLAN access point for key generation and client access must be set to a 15-character or longer complex password as required by USCYBERCOM CTO 07-15 Rev1.'
  desc 'If the organization does not use a strong passcode for client access, an adversary is significantly more likely to be able to obtain it. Once this occurs, the adversary may be able to obtain full network access, obtain DoD sensitive information, and attack other DoD information systems.'
  desc 'check', "This check only applies to access points that do not use an AAA (RADIUS) server for authentication services. In most cases, this means the access point is configured for WPA2/WPA3 (Personal), which relies on password authentication, and not WPA2/WPA3 (Enterprise), which uses a AAA server to authenticate each user based on that user's authentication credentials. 

Verify the client authentication password has been set on the access point with the following settings:
- 15 characters or more
- The authentication password selected use at least two of each of the following: uppercase letter, lowercase letter, number, and special character. 

The procedure for verifying these settings varies between AP models. Have the SA show the settings in the AP management console.

If the WLAN client password is not configured for at least a 15-character length and a complexity with at least two each of uppercase letters, lowercase letters, numbers, and special characters, this is a finding."
  desc 'fix', 'Configure the key generation password on the WLAN Access Point to a 15-character or longer complex password on access points that do not use AAA servers for authentication.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-IG Mgmt'
  tag check_id: 'C-46409r719855_chk'
  tag severity: 'medium'
  tag gid: 'V-243134'
  tag rid: 'SV-243134r719857_rule'
  tag stig_id: 'WLAN-ND-000100'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-46366r719856_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
