control 'SV-254847' do
  title 'The Tanium Operating System (TanOS) must use multifactor authentication for network access to privileged accounts.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. 

Multifactor authentication requires using two or more factors to achieve authentication. 

Factors include: (i) Something a user knows (e.g., password/PIN); (ii) Something a user has (e.g., cryptographic identification device, token); or (iii) Something a user is (e.g., biometric). 

A privileged account is defined as an information system account with authorizations of a privileged user. 

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet). 

The DOD CAC with DOD-approved PKI is an example of multifactor authentication.'
  desc 'check', '1. Sign in to the TanOS console as a user with the tanadmin role.

2. Enter "C" to go to the "User Administration" menu.

3. Enter "M" to go to the "Multi-Factor Global Settings" menu.

4. If the status shows "Multi-Factor: Optional", this is a finding.'
  desc 'fix', '1. Sign in to the TanOS console as a user with the tanadmin role.

2. Enter "C" to go to the "User Administration" menu.

3. Enter "M" to go to the "Multi-Factor Global Settings" menu.

4. Enter "M" to "Require Multi-Factor Authentication".

5. Enter "E" to "Enable Require Multi-factor Authentication".'
  impact 0.7
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58460r866080_chk'
  tag severity: 'high'
  tag gid: 'V-254847'
  tag rid: 'SV-254847r870368_rule'
  tag stig_id: 'TANS-OS-000325'
  tag gtitle: 'SRG-OS-000105'
  tag fix_id: 'F-58404r866081_fix'
  tag 'documentable'
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
