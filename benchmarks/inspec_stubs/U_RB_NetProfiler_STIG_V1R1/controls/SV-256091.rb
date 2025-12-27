control 'SV-256091' do
  title 'The Riverbed NetProfiler must be configured to protect against known types of denial-of-service (DOS) attacks by restricting web and SSH access to the appliance.'
  desc 'DOS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DOS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DOS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DOS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DOS attacks.

The security safeguards cannot be defined at the DOD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DOS attacks).'
  desc 'check', 'Go to configuration >> Appliance Security >> Password Security. 

Under Access >> Remote Access, verify the "Restrict Web access to" radio button and the "Restrict SSH access to" radio button are selected, and the boxes contain the authorized range of IP addresses. 

If this is not set, this is a finding.'
  desc 'fix', 'Go to configuration >> Appliance Security >> Password Security. 

Under Access >> Remote Access, select the "Restrict Web access to" radio button and the "Restrict SSH access to" radio button, and fill the corresponding boxes with the authorized range of IP addresses.'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59765r882779_chk'
  tag severity: 'medium'
  tag gid: 'V-256091'
  tag rid: 'SV-256091r882781_rule'
  tag stig_id: 'RINP-DM-000055'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-59708r882780_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
