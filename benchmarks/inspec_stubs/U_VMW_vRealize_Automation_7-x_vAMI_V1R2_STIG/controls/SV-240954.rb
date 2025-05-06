control 'SV-240954' do
  title 'The vAMI must have the keepaliveMaxRequest enabled.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards. These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework. There are many examples of technologies that exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy or clustering, may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(At the command prompt, execute the following command:

grep keepaliveMaxRequest /opt/vmware/etc/sfcb/sfcb.cfg | grep -vE '^#'

If the value of "keepaliveMaxRequest" is missing, commented out, less than "100", this is a finding.)
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'keepaliveMaxRequest: 100'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x vAMI'
  tag check_id: 'C-44187r676027_chk'
  tag severity: 'medium'
  tag gid: 'V-240954'
  tag rid: 'SV-240954r879806_rule'
  tag stig_id: 'VRAU-VA-000560'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-44146r676028_fix'
  tag 'documentable'
  tag legacy: ['SV-100903', 'V-90253']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
