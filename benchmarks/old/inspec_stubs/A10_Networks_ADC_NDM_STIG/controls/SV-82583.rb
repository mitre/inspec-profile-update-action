control 'SV-82583' do
  title 'The A10 Networks ADC must not use the default enable password.'
  desc 'To assure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system.

The use of a default password for any account, especially one for administrative access, can quickly lead to a compromise of the device and subsequently, the entire enclave or system. The "admin" account is intended solely for the initial setup of the device and must be disabled when the device is initially configured. The default password for this account must immediately be changed at the first logon of an authorized administrator.

The default enable password on the A10 is blank password, which can immediately be guessed and lead to a compromise. This password must be immediately set.'
  desc 'check', 'After successfully logging on to the device, attempt to enter enable mode using the default (blank) password. 

If that is successful, this is a finding.'
  desc 'fix', 'The following command changes the enable password to the character string entered: 
enable-password [newpassword]'
  impact 0.7
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68653r1_chk'
  tag severity: 'high'
  tag gid: 'V-68093'
  tag rid: 'SV-82583r1_rule'
  tag stig_id: 'AADC-NM-000145'
  tag gtitle: 'SRG-APP-000148-NDM-000246'
  tag fix_id: 'F-74207r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
