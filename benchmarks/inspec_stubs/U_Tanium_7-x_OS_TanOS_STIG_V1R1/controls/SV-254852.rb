control 'SV-254852' do
  title 'Tanium Operating System (TanOS) must terminate all network connections associated with a communications session at the end of the session, or as follows: For in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; for user sessions (nonprivileged session), the session must be terminated after 15 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press "X" for "Advanced Security," and then press "Enter".

If the "Menu Timeout" setting is "-" for "Current" or "Persistent", this is a finding.

If the "Menu Timeout" is greater than "600" (seconds) for either "Current" or "Persistent", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "A" for "Security," and then press "Enter".

5. Press "X" for "Advanced Security," and then press "Enter".

6. Press "5" for "Set Menu Timeout," and then press "Enter".

7. Enter a timeout value no greater than "600" seconds, and then press "Enter".

The timeout is not applied until a new login session is started.

8. Type "RR" and press "Enter" to return to the root menu.

9. Press "Z" for "Log out," and then press Enter.

The session will disconnect and the menu timeout will be active at next sign in.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58465r866095_chk'
  tag severity: 'medium'
  tag gid: 'V-254852'
  tag rid: 'SV-254852r866097_rule'
  tag stig_id: 'TANS-OS-000465'
  tag gtitle: 'SRG-OS-000163'
  tag fix_id: 'F-58409r866096_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
