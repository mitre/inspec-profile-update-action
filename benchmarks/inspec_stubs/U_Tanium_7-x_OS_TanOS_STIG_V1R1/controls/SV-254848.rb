control 'SV-254848' do
  title 'The Tanium Operating System (TanOS) must use multifactor authentication for network access to nonprivileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, nonprivileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication uses two or more factors to achieve authentication. 

Factors include:(i) Something you know (e.g., password/PIN); (ii) Something you have (e.g., cryptographic identification device, token); or (iii) Something you are (e.g., biometric). 

A nonprivileged account is any information system account with authorizations of a nonprivileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

The DoD CAC with DoD-approved PKI is an example of multifactor authentication.'
  desc 'check', '1. Sign in to the TanOS console as a user with the tanadmin role.

2. Enter "C" to go to the "User Administration" menu.

3. Enter "M" to go to the "Multi-Factor Global Settings" menu.

4. If the status shows "Multi-Factor: Optional", this is a finding.'
  desc 'fix', '1. Sign in to the TanOS console as a user with the tanadmin role.

2. Enter "C" to go to the "User Administration" menu.

3. Enter "M" to go to the "Multi-Factor Global Settings" menu.

4. Enter "M" to "Require Multi-Factor Authentication".

5. Enter "E" to "Enable Require Multi-factor Authentication".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58461r866083_chk'
  tag severity: 'medium'
  tag gid: 'V-254848'
  tag rid: 'SV-254848r866085_rule'
  tag stig_id: 'TANS-OS-000330'
  tag gtitle: 'SRG-OS-000106'
  tag fix_id: 'F-58405r866084_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
