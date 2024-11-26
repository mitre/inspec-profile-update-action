control 'SV-29738' do
  title 'DCOM calls are not executed under the security context of the calling user.'
  desc 'DCOM calls are executed under the security context of the calling user by default.  If the RunAs key has been altered, the DCOM calls can be executed under the user context of the currently logged in user, or as a third user.  If present, the RunAs value tells the COM Service Control Manager (SCM) the name of the account under which the server is to be activated. In addition to the account name, the COM SCM must also have the password of the account. The result of a successful logon is a security context (token) for the named account that is used as the primary token for the new COM server process. Administrators should not use this method in the evaluated configuration if accountability is required, since accountability cannot be enforced. 
RunAs values will be removed.'
  desc 'check', '·Using the Registry Editor, go to the following Registry key:

HKLM\\Software\\Classes\\Appid

·View each subkey in turn and verify that the RunAs value has not been added.
·If any subkey has a RunAs value, then this would be a finding. 

Note:   Windows components that have default Runas values such as Interactive User do not need to be changed.  Windows components that have had a Runas value added or changed and non-Windows COM objects added to the system with Runas values need to be reviewed.'
  desc 'fix', 'Remove any RunAs values from DCOM objects in the Registry.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-3107r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6830'
  tag rid: 'SV-29738r1_rule'
  tag gtitle: 'DCOM - RunAs Value'
  tag fix_id: 'F-6517r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
