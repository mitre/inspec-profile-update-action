control 'SV-77271' do
  title 'The Palo Alto Networks security platform must not use the default admin account password.'
  desc 'To assure accountability and prevent unauthenticated access, organizational administrators must be uniquely identified and authenticated for all network management accesses to prevent potential misuse and compromise of the system.

The use of a default password for any account, especially one for administrative access, can quickly lead to a compromise of the device and subsequently, the entire enclave or system.  The "admin" account is intended solely for the initial setup of the device and must be disabled when the device is initially configured.  The default password for this account must immediately be changed at the first login of an authorized administrator.'
  desc 'check', 'Open a web browser at an authorized workstation and enter the management IP address of the Palo Alto Networks security platform.
Use HTTP Secure (HTTPS) instead of HTTP since HTTP is disabled by default.
The logon window will appear.
Enter "admin" into both the "Name" and "Password" fields.  
If anything except the logon screen with the message "Invalid username or password" appears, this is a finding.'
  desc 'fix', 'Go to Device >> Administrators
Select the admin user.
In the "Old Password" field, enter "admin".
In the "New Password" field, enter the new password.
In the "Confirm New Password" field, enter the new password.
Select "OK".
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.7
  ref 'DPMS Target Palo Alto Networks Security Platform NDM'
  tag check_id: 'C-63589r1_chk'
  tag severity: 'high'
  tag gid: 'V-62781'
  tag rid: 'SV-77271r1_rule'
  tag stig_id: 'PANW-NM-000143'
  tag gtitle: 'SRG-APP-000148-NDM-000246'
  tag fix_id: 'F-68701r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
