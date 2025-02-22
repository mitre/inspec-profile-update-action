control 'SV-18862' do
  title 'The VTC system and components must not display passwords in clear text.'
  desc 'As any information is entered on a keyboard, the keyboard sends each keystroke to the processing unit which, typically, echoes the character represented by the keystroke to the display device as feedback to the system’s user. Such echoing is done in what is called “clear text” in that you can read what was entered. This process is used for normal typing, but must be changed when entering passwords. When passwords are displayed (echoed) during logon, the risk of password compromise is increased and password confidentiality is greatly reduced. If the password is displayed during logon, it can easily be compromised through the use of a simple technique of shoulder surfing, i.e., a third party witnessing the logon could view the echoed password and remember it or write it down. This could also happen through surveillance methods. This presents a major vulnerability to the security or confidential nature of the password. To mitigate this, when entering a password, the characters that are echoed to the display must be something other than the clear text characters. Typically an asterisk or other punctuation character is used to replace the actual characters in an echoed password.'
  desc 'check', 'Review site documentation to confirm the VTC system and components does not display passwords in clear text when logging onto a VTU locally or remotely. If the VTC system or any components do display passwords in clear text, this is a finding. 

Note: During APL testing, this is a finding in the event this requirement is not supported by the VTU.'
  desc 'fix', 'Implement the VTC system and components to not display passwords in clear text. If existing devices do not support this behavior, upgrade as soon as possible.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18958r6_chk'
  tag severity: 'medium'
  tag gid: 'V-17688'
  tag rid: 'SV-18862r3_rule'
  tag stig_id: 'RTS-VTC 2022.00'
  tag gtitle: 'RTS-VTC 2022'
  tag fix_id: 'F-17585r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
