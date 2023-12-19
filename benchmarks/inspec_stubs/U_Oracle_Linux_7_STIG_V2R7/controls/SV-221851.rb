control 'SV-221851' do
  title 'The Oracle Linux operating system must be configured so that all network connections associated with SSH traffic terminate after a period of inactivity.'
  desc 'Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Verify the operating system automatically terminates a user session after inactivity time-outs have expired.

Check for the value of the "ClientAliveCountMax" keyword with the following command:

# grep -i clientalivecount /etc/ssh/sshd_config
ClientAliveCountMax 0

If "ClientAliveCountMax" is not set to "0", this is a finding.'
  desc 'fix', 'Configure the operating system to terminate automatically a user session after inactivity time-outs have expired or at shutdown.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

ClientAliveCountMax 0

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23566r419625_chk'
  tag severity: 'medium'
  tag gid: 'V-221851'
  tag rid: 'SV-221851r603260_rule'
  tag stig_id: 'OL07-00-040340'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-23555r419626_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag legacy: ['V-99441', 'SV-108545']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
