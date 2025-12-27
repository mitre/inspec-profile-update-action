control 'SV-237815' do
  title 'The storage system must terminate all network connections associated with a communications session at the end of the session, at shutdown, or after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communication sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

'
  desc 'check', 'Verify the remote session timeout is set to 10 minutes or less with the following command:

cli% showsys -param

If the output does not contain the information below, this is a finding.

SessionTimeout : 00:10:00'
  desc 'fix', 'Configure the remote session timeout period (in minutes) with the following command:

cli% setsys SessionTimeout 10m'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.2.x'
  tag check_id: 'C-41025r647852_chk'
  tag severity: 'medium'
  tag gid: 'V-237815'
  tag rid: 'SV-237815r647854_rule'
  tag stig_id: 'HP3P-32-001003'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-40984r647853_fix'
  tag satisfies: ['SRG-OS-000126-GPOS-00066', 'SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag legacy: ['SV-85109', 'V-70487']
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002361']
  tag nist: ['MA-4 e', 'SC-10', 'AC-12']
end
