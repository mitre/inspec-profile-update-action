control 'SV-35107' do
  title 'The smb.conf file must use the hosts option to restrict access to Samba.'
  desc 'Samba increases the attack surface of the system and must be restricted to communicate only with systems requiring access.'
  desc 'fix', 'Edit the smb.conf file and set the hosts option to permit only authorized hosts access Samba. An example might be:
hosts allow = 127.0.0.1 192.168.2.0/24 192.168.3.0/24
hosts deny = 0.0.0.0/0
The above will only allow SMB connections from the localhost and from the two private networks 192.168.2 and 192.168.3. All other connections will be refused as soon as the client sends its first packet.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-1030'
  tag rid: 'SV-35107r1_rule'
  tag stig_id: 'GEN006220'
  tag gtitle: 'GEN006220'
  tag fix_id: 'F-32079r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
