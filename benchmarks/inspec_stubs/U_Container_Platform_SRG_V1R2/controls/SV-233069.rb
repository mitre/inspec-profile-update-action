control 'SV-233069' do
  title 'Configuration files for the container platform must be protected.'
  desc 'The secure configuration of the container platform must be protected by disallowing changes to be implemented by non-privileged users. Changes to the container platform can introduce security risks or stability issues and undermine change management procedures. Securing configuration files from non-privileged user modification can be enforced using file ownership and permissions.'
  desc 'check', 'Review the container platform to verify that configuration files cannot be modified by non-privileged users. 

If non-privileged users can modify configuration files, this is a finding.'
  desc 'fix', 'Configure the container platform to only allow configuration modifications by privileged users.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36005r600694_chk'
  tag severity: 'medium'
  tag gid: 'V-233069'
  tag rid: 'SV-233069r600696_rule'
  tag stig_id: 'SRG-APP-000133-CTR-000305'
  tag gtitle: 'SRG-APP-000133'
  tag fix_id: 'F-35973r600695_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
