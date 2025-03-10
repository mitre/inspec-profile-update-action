control 'SV-246857' do
  title 'The HYCU server and Web UI must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after 15 minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.'
  desc 'check', 'Log on to the HYCU VM console. For console connections, check for the value of the "TMOUT" option in "/home/hycu/.bashrc" with the following command:
grep TMOUT /home/hycu/.bashrc

If the "TMOUT" value is not set to 900 or less, this is a finding.

For SSH connections, check for the value of the "ClientAliveInterval" option in "/etc/ssh/sshd_config" with the following command:
grep ClientAliveInterval /etc/ssh/sshd_config

If the "ClientAliveInterval" value is not set to 15 or less, this is a finding.

For UI connections, run the following command to check configured HYCU session timeout:
cat /opt/grizzly/config.properties | grep api.session.expiration.minutes

If not configured at "15" or less, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce timeout settings.

Add the following line to "/home/hycu/.bashrc" (or modify the line to have the required value):
TMOUT=900

Add the following line to "/etc/ssh/sshd_config" (or modify the line to have the required value):
ClientAliveInterval 900

Edit the "/opt/grizzly/config.properties" file by running:
sudo vi /opt/grizzly/config.properties

Add the following line or modify the line to have the required value:
api.session.expiration.minutes=15

Save the file by typing:
:wq!'
  impact 0.7
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50289r768233_chk'
  tag severity: 'high'
  tag gid: 'V-246857'
  tag rid: 'SV-246857r768243_rule'
  tag stig_id: 'HYCU-SC-000001'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-50243r768234_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
