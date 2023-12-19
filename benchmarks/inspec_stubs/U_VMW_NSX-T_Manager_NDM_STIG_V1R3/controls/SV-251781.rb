control 'SV-251781' do
  title 'The NSX-T Manager must terminate the device management session at the end of the session or after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, or de-allocating networking assignments at the application level if multiple application sessions are using a single, operating system-level network connection. This does not mean that the device terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'From an NSX-T Manager shell, run the following command(s):

>  get service http | find Session

Expected result:
Session timeout:  600

If the output does not match the expected result, this is a finding.

From an NSX-T Manager shell, run the following command(s):

>  get cli-timeout

Expected result:
600 seconds

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'From an NSX-T Manager shell, run the following command(s):

> set service http session-timeout 600
> set cli-timeout 600'
  impact 0.7
  ref 'DPMS Target VMware NSX-T Manager NDM'
  tag check_id: 'C-55241r810344_chk'
  tag severity: 'high'
  tag gid: 'V-251781'
  tag rid: 'SV-251781r916342_rule'
  tag stig_id: 'TNDM-3X-000052'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-55195r810345_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
