control 'SV-254841' do
  title 'The Tanium Operating System (TanOS) must limit the number of concurrent sessions to an organization-defined number for all accounts and/or account types.'
  desc 'Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press "P" for "Security Policy," and then press "Enter".

6. Press "M" for "Maximum Concurrent Logins," and then press "Enter".

7. Work with the Tanium Administrator to confirm the number of maximum concurrent users.

If the value of "Maximum Concurrent Logins:" is greater than the approved value, this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press P for "Security Policy," and then press "Enter".

6. Press "M" for "Maximum Concurrent Logins," and then press "Enter".

7. Work with the Tanium Administrator to set the number of maximum concurrent users.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58454r866062_chk'
  tag severity: 'medium'
  tag gid: 'V-254841'
  tag rid: 'SV-254841r866064_rule'
  tag stig_id: 'TANS-OS-000095'
  tag gtitle: 'SRG-OS-000027'
  tag fix_id: 'F-58398r866063_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
