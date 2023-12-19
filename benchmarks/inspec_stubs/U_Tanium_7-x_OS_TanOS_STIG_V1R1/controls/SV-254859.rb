control 'SV-254859' do
  title 'Tanium Operating System (TanOS) must automatically terminate a user session after organization-defined conditions or trigger events requiring session disconnect.'
  desc 'Automatic session termination addresses the termination of user-initiated logical sessions in contrast to the termination of network connections that are associated with communications sessions (i.e., network disconnect). A logical session (for local, network, and remote access) is initiated whenever a user (or process acting on behalf of a user) accesses an organizational information system. Such user sessions can be terminated (and thus terminate user access) without terminating network sessions.'
  desc 'check', '1. Sign in to the TanOS console as a user with the tanadmin role. 

2. Enter "A" to go to the "Appliance Configuration" menu. 

3. Enter "A" to go to the "Security" menu. 

4. Enter "X" to go to the "Advanced Security" menu. 

5. Enter "5" to go to "Set Menu Timeout". 

6. See the current setting for timeout, if this does not match the organizationally defined standard, this is a finding.'
  desc 'fix', '1. Sign in to the TanOS console as a user with the tanadmin role. 

2. Enter "A" to go to the "Appliance Configuration" menu. 

3. Enter "A" to go to the "" menu. 

4. Enter "X" to go to the "Advanced Security" menu. 

5. Enter "5" to go to "Set Menu Timeout". 

6. Enter the correct Timeout in seconds, and then press "Enter" to set the setting.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58472r866116_chk'
  tag severity: 'medium'
  tag gid: 'V-254859'
  tag rid: 'SV-254859r866118_rule'
  tag stig_id: 'TANS-OS-000735'
  tag gtitle: 'SRG-OS-000279'
  tag fix_id: 'F-58416r866117_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
