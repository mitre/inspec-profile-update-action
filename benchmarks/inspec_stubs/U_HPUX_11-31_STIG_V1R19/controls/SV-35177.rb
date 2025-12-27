control 'SV-35177' do
  title 'IP forwarding for IPv4 must not be enabled, unless the system is a router.'
  desc 'If the system is configured for IP forwarding and is not a designated router, it could be used to bypass network security by providing a path for communication not filtered by network devices.'
  desc 'check', %q(The configuration file entries will appear as follows:
TRANSPORT_NAME[x]=ip
NDD_NAME[x]=ip_forwarding
NDD_VALUE[x]=0
NOTE: The setting for the "ip_forwarding" interface will be initialized on a separate line referencing a specific NDD index.

# cat /etc/rc.config.d/nddconf | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | grep -v '^#' | \
 	grep -i ip_forwarding | cut -f 1,1 -d "=" | tr -d  [:alpha:] | tr -d [:punct:]

If the above command returns nothing, this check is not a finding.

If the above command does return an index value:
# cat /etc/rc.config.d/nddconf | tr '\011' ' ' | tr -s  ' ' | sed -e 's/^[  \t]*//'  | grep -v '^#' | \
 	grep "[the ip_forwarding INDEX number from the above command]" 

NOTE: The above command must (literally) contain the ASCII punctuation characters [ and ] exactly as depicted above. 

If the return value is not set to 0, ask the SA if the machine is a designated router. If it is not a designated router, this is a finding. If it is a designated router, this is not a finding.)
  desc 'fix', 'Edit /etc/rc.config.d/nddconf and set the ip_forwarding option to 0.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36675r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12023'
  tag rid: 'SV-35177r1_rule'
  tag stig_id: 'GEN005600'
  tag gtitle: 'GEN005600'
  tag fix_id: 'F-32046r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
