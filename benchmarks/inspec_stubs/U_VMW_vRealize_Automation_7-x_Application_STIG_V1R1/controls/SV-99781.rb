control 'SV-99781' do
  title 'The vRealize Automation security file must be restricted to the vcac user.'
  desc 'Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges. 

The vRealize Automation product stores important system information in the security.properties file. Preventing access to this file from non-privileged is essential to ensure the integrity and confidentiality of vRA.'
  desc 'check', 'At the command prompt, execute the following command:

ls -l /etc/vcac/security.properties

If the file owner and group-owner are not "vcac", this is a finding.'
  desc 'fix', 'At the command prompt, execute the following commands:

chown vcac:vcac /etc/vcac/security.properties'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x Application'
  tag check_id: 'C-88823r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89131'
  tag rid: 'SV-99781r1_rule'
  tag stig_id: 'VRAU-AP-000400'
  tag gtitle: 'SRG-APP-000340-AS-000185'
  tag fix_id: 'F-95873r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
