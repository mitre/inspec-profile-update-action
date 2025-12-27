control 'SV-21495' do
  title 'Unified messaging and email text-to-speech features must be disabled because there is no PKI authentication and no access control to email.'
  desc 'Unified messaging and email systems provide the capability to receive voicemails via email and in some cases, have emails read to the user via a text-to-speech feature when accessing the system from a telephone (dial-in). For DoD, this presents two issues or vulnerabilities. Access to voicemail from a telephone only requires the user’s telephone number and a PIN. The telephone number is the account or mailbox number on the voicemail system while the PIN is the user password for accessing the account. This is a rather weak authentication method. The first issue for DoD, is that DoD policy states that access to email requires PKI based authentication of the user before they are granted access to their email account. PKI certificates are required to decrypt encrypted email. PKI authentication is not available when using a standard telephone. While some organizations might implement PKI authenticated access to the site’s phone system, such a facility is not available via most DoD phone systems and certainly not via the PSTN. Additionally, while a non-PKI enabled text-to-speech feature would not be able to read encrypted email (which would be considered the most sensitive) the unencrypted email is still considered sensitive DoD information. The argument could be made that normal voicemail messages and regular telephone conversations can also contain sensitive information. However, there is typically more sensitive information in email. This does not apply to DoD issued PDA/PED devices that provide CAC authenticated access to email. Access to unified mail voicemail would be via PKI authenticated email service through which the user could listen to the voicemail. Text-to-speech conversion would be permitted in this case even though caution should be used when listening to any voicemail, particularly in a public place. The use of a wired earphone is highly recommended. The use of Bluetooth, DECT/DECT 6.0, and other RF wireless technologies for accessories must be approved.'
  desc 'check', 'Interview the ISSO to validate compliance with the following requirement: 

In the event an email text-to-speech feature is employed or enabled in a unified messaging and email system, and accessed via the dial-in voicemail access method, ensure DoD PKI authentication is used to access the feature as is required for normal email access control. Otherwise, disable the text-to-speech feature as well as any other dial-up method that does not provide for PKI authentication for accessing email. 

Determine if the site has implemented a unified mail system where voicemail is delivered via the user’s email mailbox. This will normally imply that email could be available via normal voicemail access from a standard telephone and that the email is read to the user via a text-to-speech conversion feature. Inspect the configuration of the unified messaging and email server to determine if the text-to-speech feature is disabled. Alternately have the ISSO or SA demonstrate compliance with the requirement.

If email is accessible via voicemail without PKI authentication, this is a finding.

NOTE: Access to the email service must already be in compliance with DoD email access policy using PKI. Therefore, this requirement does not apply to accessing and listening to voicemail via the email service.'
  desc 'fix', 'In the event an email text-to-speech feature is employed or enabled in a unified messaging system, and accessed via the dial-in voicemail access method, ensure PKI based authentication is used to access the feature as is required for normal email access control. Otherwise, disable the text-to-speech feature as well as any other dial-up method that does not provide for PKI authentication for accessing email. 

Disable the text-to-speech feature of a unified mail service.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23713r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19444'
  tag rid: 'SV-21495r3_rule'
  tag stig_id: 'VVoIP 1755'
  tag gtitle: 'VVoIP 1755'
  tag fix_id: 'F-20189r2_fix'
  tag 'documentable'
end
