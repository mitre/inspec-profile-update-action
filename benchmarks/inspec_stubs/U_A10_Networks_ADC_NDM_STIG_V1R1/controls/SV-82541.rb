control 'SV-82541' do
  title 'The A10 Networks ADC must not use the default admin account.'
  desc 'To assure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system.

The use of a default password for any account, especially one for administrative access, can quickly lead to a compromise of the device and subsequently, the entire enclave or system. The "admin" account is intended solely for the initial setup of the device and must be disabled when the device is initially configured. The default password for this account must immediately be changed at the first logon of an authorized administrator.

The ACOS device comes with one admin account, "admin", by default. The "admin" account has global Read Write privileges. The admin account, and other admin accounts with global Read Write privileges, can configure additional admin accounts. Since this account, if misused, can easily compromise the device, it must be disabled.'
  desc 'check', 'Attempt to log on to the device using the default administrator logon and password. 

If the logon is successful, this is a finding.

Review the device configuration.

The following command shows all of the configured accounts on the device:
show admin

If the admin account is enabled, this is a finding.'
  desc 'fix', 'The following command changes the admin password for the account "admin" to the character string entered:
admin admin password [newpassword]
The prompt will change to show that the admin account is being configured.

The following command disables the account:
disable'
  impact 0.7
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68611r1_chk'
  tag severity: 'high'
  tag gid: 'V-68051'
  tag rid: 'SV-82541r1_rule'
  tag stig_id: 'AADC-NM-000048'
  tag gtitle: 'SRG-APP-000148-NDM-000246'
  tag fix_id: 'F-74167r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
