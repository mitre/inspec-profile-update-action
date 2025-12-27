control 'SV-239449' do
  title 'The SLES for vRealize must initiate a session lock after a 15-minute period of inactivity for an SSH connection.'
  desc "A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, SLES for vRealize needs to be able to identify when a user's session has idled and take action to initiate the session lock.

The session lock is implemented at the point where session activity can be determined and/or controlled."
  desc 'check', 'Verify SLES for vRealize initiates a session lock after a 15-minute period of inactivity for SSH. 

Execute the following command:

# grep ClientAliveInterval /etc/ssh/sshd_config; grep  ClientAliveCountMax /etc/ssh/sshd_config

Verify the following result:

ClientAliveInterval 900 
ClientAliveCountMax 0

If the session lock is not set to a 15-minute period, this is a finding.'
  desc 'fix', "Configure SLES for vRealize to initiate a session lock after a 15-minute period of inactivity for SSH.

Set the session lock after a 15-minute period by executing the following command:

# sed -i 's/^.*\\bClientAliveInterval\\b.*$/ClientAliveInterval 900/' /etc/ssh/sshd_config; sed -i 's/^.*\\bClientAliveCountMax\\b.*$/ClientAliveCountMax 0/' /etc/ssh/sshd_config"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42682r661796_chk'
  tag severity: 'medium'
  tag gid: 'V-239449'
  tag rid: 'SV-239449r661798_rule'
  tag stig_id: 'VROM-SL-000055'
  tag gtitle: 'SRG-OS-000029-GPOS-00010'
  tag fix_id: 'F-42641r661797_fix'
  tag 'documentable'
  tag legacy: ['SV-99019', 'V-88369']
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
