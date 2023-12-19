control 'SV-254850' do
  title 'The Tanium Operating System (TanOS) must terminate all sessions and network connections when nonlocal maintenance is completed.'
  desc 'Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press "X" for "Advanced Security," and then press "Enter".

If the "Menu Timeout" setting is "-", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press "X" for "Advanced Security," and then press "Enter".

6. Press "5" for "Set Menu Timeout," and then press "Enter".

7. Enter the desired SSH timeout in seconds, and then press "Enter".'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58463r866089_chk'
  tag severity: 'medium'
  tag gid: 'V-254850'
  tag rid: 'SV-254850r866091_rule'
  tag stig_id: 'TANS-OS-000410'
  tag gtitle: 'SRG-OS-000126'
  tag fix_id: 'F-58407r866090_fix'
  tag 'documentable'
  tag cci: ['CCI-000879']
  tag nist: ['MA-4 e']
end
