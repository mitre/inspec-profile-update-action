control 'SV-83815' do
  title 'The NSX Manager must enforce access restrictions associated with changes to the system components.'
  desc 'Changes to the hardware or software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals must be allowed administrative access to the network device for implementing any changes or upgrades. This requirement applies to updates of the application files, configuration, ACLs, and policy filters.'
  desc 'check', 'Verify the built-in SSO administrator account is only used for emergencies and situations where it is the only option due to permissions. 

If the built-in SSO administrator account is used for daily operations or there is no policy restricting its use, this is a finding.'
  desc 'fix', 'Develop a policy to limit the use of the built-in SSO administrator account.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69651r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69211'
  tag rid: 'SV-83815r1_rule'
  tag stig_id: 'VNSX-ND-000133'
  tag gtitle: 'SRG-APP-000516-NDM-000335'
  tag fix_id: 'F-75397r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000345', 'CCI-000366']
  tag nist: ['CM-5', 'CM-6 b']
end
