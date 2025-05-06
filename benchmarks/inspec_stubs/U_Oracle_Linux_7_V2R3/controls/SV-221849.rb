control 'SV-221849' do
  title 'The Oracle Linux operating system must be configured so that all network connections associated with SSH traffic are terminated at the end of the session or after 10 minutes of inactivity, except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Verify the operating system automatically terminates a user session after inactivity time-outs have expired.

Check for the value of the "ClientAliveInterval" keyword with the following command:

# grep -iw clientaliveinterval /etc/ssh/sshd_config

ClientAliveInterval 600

If "ClientAliveInterval" is not configured, commented out, or has a value of "0", this is a finding.

If "ClientAliveInterval" has a value that is greater than "600" and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.'
  desc 'fix', 'Configure the operating system to terminate a user session automatically after inactivity time-outs have expired or at shutdown.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

ClientAliveInterval 600

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23564r419619_chk'
  tag severity: 'medium'
  tag gid: 'V-221849'
  tag rid: 'SV-221849r603260_rule'
  tag stig_id: 'OL07-00-040320'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-23553r419620_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag legacy: ['SV-108541', 'V-99437']
  tag cci: ['CCI-002361', 'CCI-001133']
  tag nist: ['AC-12', 'SC-10']
end
