control 'SV-251029' do
  title 'The Sentry must terminate all network connections associated with a communications session at the end of the session, or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity; and for mobile device sessions (non-privileged session), the session must be terminated after 15 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system level network connection.

ALGs may provide session control functionality as part of content filtering, load balancing, or proxy services.'
  desc 'check', '1. Log in to the Core Admin Portal.
2. Go to Policies and Configurations >> Configurations.
3. Click on existing VPN Configuration for MobileIron Tunnel; verify "Connection Type" is set to "MobileIron Tunnel".
4. Go to "Custom Data" section at the bottom and find the following Key Value pair: "TcpIdleTmoMs"

The default idle timeout for the session is 1 hour. Therefore, if the key value pair is missing, this is a finding.

If the key value pair is present, verify the value is no greater than 900000 millisec (15 min).

If key value pair is not present or is set to a value greater than 900000, this is a finding.'
  desc 'fix', 'Configure Sentry to terminate all network connections associated with a communication session at 15 minutes of inactivity.

1. Log in to the Core Admin Portal.
2. Go to Policies and Configurations >> Configurations.
3. Click on existing VPN Configuration for MobileIron Tunnel; ensure "Connection Type" is set to "MobileIron Tunnel".
4. Go to "Custom Data" section at the bottom and find the following Key Value pair: "TcpIdleTmoMs"

If the key value pair is present, set the value to 900000 millisec (15 min).'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54464r802307_chk'
  tag severity: 'medium'
  tag gid: 'V-251029'
  tag rid: 'SV-251029r802309_rule'
  tag stig_id: 'MOIS-AL-000470'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-54418r802308_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
