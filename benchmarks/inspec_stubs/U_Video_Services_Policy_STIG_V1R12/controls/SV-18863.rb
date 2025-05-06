control 'SV-18863' do
  title 'The Videoconferencing system and components passwords must meet complexity and strength policy.'
  desc 'DoD policy mandates the use of strong passwords. The minimum password length is 15 characters. The minimum password complexity when not using DoD PKI is at least one lowercase letter, one uppercase letter, one number, and one special character must be present in the password. When a password is changed, at least half the characters in the password must change; for a 15-character password this mandates eight positions, and for a four-digit PIN at least two numbers would change.

While videoconferencing endpoints typically do not require a username, they do require a password for user access and authentication. The strength of these passwords is an issue for video endpoints and is dependent upon the method of entry. Strong passwords, along with other measures noted in DoD policy, are required for any access method that is received by the video endpoint across a network. This is because of the potential that a password could be broken by a variety of high-speed cracking attacks. Due to the inability to use letters, PINs are very weak passwords. Typically, a local video endpoint PIN entered from a hand-held remote control can support five or more characters.'
  desc 'check', 'Review site documentation to confirm a policy and procedure requires the videoconferencing system and components to have passwords meeting complexity or strength policy, as follows:
- PINs entered into a local video endpoint from a hand-held remote control must contain at least six digits.
- PINs entered into a remote video endpoint from a hand-held remote control must contain at least nine digits.
- Passwords entered from a keyboard must contain at least at least 15 characters with at least one lowercase letter, one uppercase letter, one number, and one special character. 
- Passwords and PINs must be encrypted per DoD standards. 

If the videoconferencing system and components do not have passwords meeting complexity or strength policy, this is a finding.'
  desc 'fix', 'Implement videoconferencing system and components passwords to meet complexity and strength policy.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18959r3_chk'
  tag severity: 'medium'
  tag gid: 'V-17689'
  tag rid: 'SV-18863r4_rule'
  tag stig_id: 'RTS-VTC 2024.00'
  tag gtitle: 'RTS-VTC 2024'
  tag fix_id: 'F-17586r3_fix'
  tag 'documentable'
  tag severity_override_guidance: 'Reduced to CAT III when a five-digit PIN is used for video endpoint local access from the hand-held remote control.
Reduced to CAT III when an eight-character password is used for video endpoint remote access and contains a mix of upper case letters, lower case letters, numbers, and special characters.
Reduced to CAT III when the site develops and enforces a policy or procedure to manage password length and complexity to mitigate deficiencies in video endpoint enforcement of password complexity and length.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Other']
end
