control 'SV-100901' do
  title 'The vAMI must have the keepaliveTimeout enabled.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. To reduce the possibility or effect of a DoS, the application server must employ defined security safeguards. These safeguards will be determined by the placement of the application server and the type of applications being hosted within the application server framework. There are many examples of technologies that exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy or clustering, may reduce the susceptibility to some DoS attacks.'
  desc 'check', %q(At the command prompt, execute the following command:

grep keepaliveTimeout /opt/vmware/etc/sfcb/sfcb.cfg | grep -vE '^#'

If the value of "keepaliveTimeout" is missing, commented out, or less than "15", this is a finding.)
  desc 'fix', "Navigate to and open /opt/vmware/etc/sfcb/sfcb.cfg.

Configure the sfcb.cfg file with the following value: 'keepaliveTimeout: 15'"
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89943r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90251'
  tag rid: 'SV-100901r1_rule'
  tag stig_id: 'VRAU-VA-000555'
  tag gtitle: 'SRG-APP-000435-AS-000163'
  tag fix_id: 'F-96993r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
