control 'SV-102393' do
  title 'The SEL-2740S must be configured to permit the maintenance and diagnostics communications to specified OTSDN Controller(s).'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (e.g., firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'To ensure SEL-2740S necessary diagnostics and maintenance communications, do the following:
1. Log in with Permission Level 3 rights into parent OTSDN Controller.
2. Confirm the desired switch is adopted by checking that there is a green solid border around the switch in the UI on the topology page.
3. Click the switch node and then the Device View button.
4. Confirm a new browser page opens for the diagnostic collection of the switch.  

If the SEL-2740S is not successfully talking to the flow controller, this is a finding.'
  desc 'fix', 'The adoption of SEL-2740S switches when using SEL-5056 flow controller will have saturation protection automatically enabled using flow meters between the switch and the flow controller. To configure this simply adopt the switches using the default flows which rate limit traffic to the flow controller. 
1. Log in to SEL-5056 using Permission Level 3.
2. Confirm all switches are adopted and if not create a configuration object with desired settings and use the new object to adopt the switch.
3. When adoption is complete the flows between the switch and the flow controller use a meter, navigate to the meter page and confirm a new meter was created for that switch and is in the "success" state.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91601r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92305'
  tag rid: 'SV-102393r1_rule'
  tag stig_id: 'SELS-ND-001190'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-98543r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
