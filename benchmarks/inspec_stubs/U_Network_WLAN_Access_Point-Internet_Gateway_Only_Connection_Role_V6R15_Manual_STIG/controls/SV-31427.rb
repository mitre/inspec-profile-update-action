control 'SV-31427' do
  title 'The password configured on the WLAN Access Point for key generation and client access must be set to a 14 character or longer complex password as required by USCYBERCOM CTO 07-15Rev1.'
  desc 'If the organization does not use a strong passcode for client access, then it is significantly more likely that an adversary will be able to obtain it.  Once this occurs, the adversary may be able to obtain full network access, obtain DoD sensitive information, and attack other DoD information systems.'
  desc 'check', 'This check only applies to access points that do not use an AAA (RADIUS) server for authentication services.  In most cases, this means the access point is configured for WPA2 (Personal), which relies on password authentication, and not WPA2 (Enterprise) which uses an AAA server to authenticate each user based on that user’s authentication credentials. 
Verify the client authentication password has been set on the access point with the following settings:

-14 characters or longer.
-The authentication password selected must be comprised of at least two of each of the following: upper case letter, lower case letter, number, and special character. 

The procedure for verifying these settings varies between AP models. Have the SA show the settings in the AP management console.'
  desc 'fix', 'The key generation password configured on the WLAN Access Point must be set to a 14-character or longer complex password on access points that do not use AAA servers for authentication.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-31751r2_chk'
  tag severity: 'medium'
  tag gid: 'V-25316'
  tag rid: 'SV-31427r2_rule'
  tag stig_id: 'WIR0122'
  tag gtitle: 'WLAN Access Point passcode'
  tag fix_id: 'F-28236r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
