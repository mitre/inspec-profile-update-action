control 'SV-254844' do
  title 'The Tanium Operating System (TanOS) must enforce a 60-day maximum password lifetime restriction.'
  desc 'Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. 

One method of minimizing this risk is to use complex passwords and periodically change them. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

If the "Password Maximum Age (days)" is not set to "60", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "C" for "User Administration Menu".

4. Press "L" for "Local Tanium User Management".

5. Press "B" for "Security Policy Local Authentication Service".

6. Type "Yes".

7. Press "Enter" to accept the current value for "Define the minimum password in days [0 - 20]".

8. Set the value of "Define the maximum password lifetime in days [0-300]" to "60".

9. Press "Enter" to accept the current values for the rest of the options.

10. Type "Yes" to apply the new security policy.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58457r866071_chk'
  tag severity: 'medium'
  tag gid: 'V-254844'
  tag rid: 'SV-254844r866073_rule'
  tag stig_id: 'TANS-OS-000275'
  tag gtitle: 'SRG-OS-000076'
  tag fix_id: 'F-58401r866072_fix'
  tag 'documentable'
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
