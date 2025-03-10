control 'SV-4262' do
  title 'The system must not have the rpc.ugidd daemon enabled.'
  desc 'The rpc.ugidd daemon could be used by a remote attacker to list all users on a specific system.  Once the user IDs have been obtained, a system could be compromised through brute-force password hacking.'
  desc 'check', 'To check for the rpc.ugidd daemon perform:

	#	chkconfig –list rpc.ugidd

Or

	# ps –ef | grep –i ugidd

If the daemon is running or installed this is a finding.'
  desc 'fix', 'If the rpc.ugidd daemon is installed, disable it using the chkconfig utility.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-2086r2_chk'
  tag severity: 'medium'
  tag gid: 'V-4262'
  tag rid: 'SV-4262r2_rule'
  tag stig_id: 'GEN000000-LNX00300'
  tag gtitle: 'GEN000000-LNX00300'
  tag fix_id: 'F-4173r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
