control 'SV-246820' do
  title 'The HYCU 4.1 application and server must initiate a session lock after a 15-minute period of inactivity.'
  desc 'A session lock is a temporary network device or administrator-initiated action taken when the administrator stops work but does not log out of the network device. Rather than relying on the user to manually lock their management session prior to vacating the vicinity, network devices need to be able to identify when a management session has idled and take action to initiate the session lock. Once invoked, the session lock must remain in place until the administrator reauthenticates. No other system activity aside from reauthentication must unlock the management session.'
  desc 'check', 'Log on to the VM console.

grep ClientAliveInterval /etc/ssh/sshd_config 

If "ClientAliveInterval" is missing or commented out, this is a finding.

If "ClientAliveInterval" exists and is configured to less than 15 minutes, this is a finding.

Log on to the Web UI console and leave the session open. Determine if the VM console session locks after 15 minutes. 

If it does not, this is a finding. 

The Web UI will also time out automatically after 15 minutes of user inactivity. 

If the Web UI session does not log out the inactive user, this is a finding.'
  desc 'fix', 'Log on to the VM console and use the following command to edit the "sshd_config" file:
vi /etc/ssh/sshd_config
ClientAliveInterval 15m          # 15 minutes
ClientAliveCountMax 0           # 0 times

Web UI by default performs an automatic logout after 15 minutes of user inactivity. Do the following to further tweak the inactivity timeout if required:

If the "config.properties" file is not yet created, copy the "config.properties.template" file to become the "config.properties" file by typing:
cp /opt/grizzly/config.properties.template /opt/grizzly/config.properties

Edit the "/opt/grizzly/config.properties" file by running:
sudo vi /opt/grizzly/config.properties

Locate the following setting:
# api.session.expiration.minutes=15 #int

Change the number from 15 to the desired value, uncomment the line by removing the #, and save the file by typing:
:wq!

Restart the grizzly service by running:
service grizzly restart'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50252r768122_chk'
  tag severity: 'medium'
  tag gid: 'V-246820'
  tag rid: 'SV-246820r768124_rule'
  tag stig_id: 'HYCU-AC-000002'
  tag gtitle: 'SRG-APP-000003-NDM-000202'
  tag fix_id: 'F-50206r768123_fix'
  tag 'documentable'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
