control 'SV-104255' do
  title 'Symantec ProxySG must terminate all network connections associated with a communications session at the end of the session or terminate user sessions (nonprivileged session) after 15 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the ProxySG.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system level network connection.

ALGs may provide session control functionality as part of content filtering, load balancing, or proxy services. Symantec ProxySG manages sessions automatically and terminates them once they become idle. The idle period is governed by parameters such as the TCP segment lifetime (default is 120 seconds) and authentication credential inactivity timeout (default is 900 seconds for all authentication types).'
  desc 'check', 'Check the two user-configurable parameters that affect session termination (TCP segment lifetime and authentication credential inactivity timeout).

Check the TCP segment lifetime setting (default is 120 seconds).
1. SSH into the ProxySG console and type "show tcp-ip".
2. Verify that the TCP 2MSL timeout is set to 600 seconds or less.

Check the authentication credential inactivity timeouts.
1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. For each authentication method listed, click it and then the "General" tab and verify that the "Inactivity timeout" is set to 600 seconds or less (default is 900 seconds).

If Symantec ProxySG does not terminate all network connections associated with a communications session at the end of the session, or terminate user sessions (nonprivileged session) after 15 minutes of inactivity, this is a finding.'
  desc 'fix', 'Configure the two user-configurable parameters that affect session termination (TCP segment lifetime and authentication credential inactivity timeout).

Configure the TCP segment lifetime setting (default is 120 seconds).
1. SSH into the ProxySG console and type "enable" and then "configure".
2. Type "tcp-ip tcp 2msl 900", for example, to set the timeout to 900 seconds (the default).

Configure the authentication credential inactivity timeouts.
1. Log on to the Web Management Console.
2. Browse to Configuration >> Authentication.
3. For each authentication method listed, click it and then the "General" tab and set the "Inactivity timeout" to 600 seconds or less (default is 900 seconds).
4. Click "Apply".'
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93487r3_chk'
  tag severity: 'high'
  tag gid: 'V-94301'
  tag rid: 'SV-104255r1_rule'
  tag stig_id: 'SYMP-AG-000440'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-100417r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
