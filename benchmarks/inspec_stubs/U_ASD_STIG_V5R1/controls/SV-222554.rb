control 'SV-222554' do
  title 'The application must not display passwords/PINs as clear text.'
  desc 'To prevent the compromise of authentication information such as passwords during the authentication process, the feedback from the information system must not provide any information that would allow an unauthorized user to compromise the authentication mechanism.

Obfuscation of user-provided information when typed into the system is a method used in addressing this risk.

For example, displaying asterisks when a user types in a password is an example of obscuring feedback of authentication information.

Another method is to display authentication feedback for a very limited time, usually in fractions of a second. This occurs during password character entry where the password characters are displayed for a very small window of time and then automatically obfuscated. This allows users with just enough time to confirm their password as they type it while limiting the ability of "shoulder surfers" to covertly witness the values.

A common tactic employed to circumvent password obfuscation is to copy the obfuscated password and paste it to a text file.  Proper obfuscation techniques will not paste the clear text password.'
  desc 'check', 'Ask the application admin to log on to the application.

Observe the authentication process and verify any display feedback provided when the admin enters her/his password is obfuscated and not clear text.

For applications that display authentication feedback for a very limited time, ensure the feedback time the character is displayed is only momentary i.e., fractions of a second.

Using a text editor, copy the obfuscated password and paste to a text file.  Do not save the file.

If the application displays clear text when the password/PIN is entered, or if the time period for displayed feedback exceeds fractions of a second, or if the clear text password/PIN is displayed when pasted, this is a finding.'
  desc 'fix', 'Configure the application to obfuscate passwords and PINs when they are being entered so they cannot be read.

Design the application so obfuscated passwords cannot be copied and then pasted as clear text.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24224r493570_chk'
  tag severity: 'high'
  tag gid: 'V-222554'
  tag rid: 'SV-222554r508029_rule'
  tag stig_id: 'APSC-DV-001850'
  tag gtitle: 'SRG-APP-000178'
  tag fix_id: 'F-24213r493571_fix'
  tag 'documentable'
  tag legacy: ['V-70157', 'SV-84779']
  tag cci: ['CCI-000206']
  tag nist: ['IA-6']
end
