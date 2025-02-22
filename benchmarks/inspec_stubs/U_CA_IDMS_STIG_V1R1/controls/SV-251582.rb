control 'SV-251582' do
  title 'For interactive sessions, IDMS must limit the number of concurrent sessions for the same user to one or allow unlimited sessions.'
  desc 'Multiple interactive sessions can provide a way to cause a DoS attack against IDMS if a user ID and password were compromised. Not allowing multiple sign-ons can mitigate the risk of malicious attacks using multiple sessions for a user.'
  desc 'check', 'Use task SYSGEN if online, or program RHDCSGEN if batch.
  
Sign on to the dictionary where the System definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "DISPLAY SYSTEM 123." where 123 is the number of the system being checked.

Scroll through the returned text until "MULTIPLE SIGNON" is found.

If the associated value is "YES", this is a finding.'
  desc 'fix', 'Use TASK SYSGEN if online, or program RHDCSGEN if batch.

Sign on to the dictionary where the system definition is maintained: "SIGNON DICTIONARY SYSTEM.", for example.

Enter: "MODIFY SYSTEM 123 MULTIPLE SIGNON IS NO." where 123 is the number of the system being modified.

Enter: "VALIDATE."

Enter: "GENERATE."

The change will become effective the next time the CV is stopped and started.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55017r807611_chk'
  tag severity: 'medium'
  tag gid: 'V-251582'
  tag rid: 'SV-251582r807613_rule'
  tag stig_id: 'IDMS-DB-000010'
  tag gtitle: 'SRG-APP-000001-DB-000031'
  tag fix_id: 'F-54971r807612_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
