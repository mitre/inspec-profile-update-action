control 'SV-255271' do
  title 'The HPE 3PAR OS must be configured to terminate all network connections associated with a communications session at the end of the session, or after 10 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

If a maintenance session or connection remains open after maintenance is completed, it may be hijacked by an attacker and used to compromise or damage the system.

Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network (e.g., the internet) or an internal network. Local maintenance and diagnostic activities are those activities carried out by individuals physically present at the information system or information system component and not communicating across a network connection.

Under normal circumstances, a service user would log out of the array when maintenance is complete, and the session/connection would be terminated. Setting an acceptable inactivity timeout will guarantee that sessions cannot remain idle if they were not cleanly terminated.

'
  desc 'check', 'Verify the current SessionTimeout setting:

cli% showsys -param

Find the line in the output for SessionTimeout, if the value is not "00:10:00", this is a finding.'
  desc 'fix', 'Set the SessionTimeout value to 10 minutes:

cli% setsys SessionTimeout 10m'
  impact 0.5
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58944r870130_chk'
  tag severity: 'medium'
  tag gid: 'V-255271'
  tag rid: 'SV-255271r870132_rule'
  tag stig_id: 'HP3P-33-001003'
  tag gtitle: 'SRG-OS-000126-GPOS-00066'
  tag fix_id: 'F-58888r870131_fix'
  tag satisfies: ['SRG-OS-000126-GPOS-00066', 'SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109']
  tag 'documentable'
  tag cci: ['CCI-000879', 'CCI-001133', 'CCI-002361']
  tag nist: ['MA-4 e', 'SC-10', 'AC-12']
end
