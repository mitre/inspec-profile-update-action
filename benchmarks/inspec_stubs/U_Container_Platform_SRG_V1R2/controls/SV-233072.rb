control 'SV-233072' do
  title 'The container platform registry must contain only container images for those capabilities being offered by the container platform.'
  desc 'Allowing container images to reside within the container platform registry that are not essential to the capabilities being offered by the container platform becomes a potential security risk. By allowing these non-essential container images to exist, the possibility for accidental instantiation exists. The images may be unpatched, not supported, or offer non-approved capabilities. Those images for customer services are considered essential capabilities.'
  desc 'check', 'Review the container platform registry and the container images being stored. 

If container images are stored in the registry and are not being used to offer container platform capabilities, this is a finding.'
  desc 'fix', 'Remove all container images from the container platform registry that are not being used or contain features and functions not supported by the platform.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36008r600703_chk'
  tag severity: 'medium'
  tag gid: 'V-233072'
  tag rid: 'SV-233072r600705_rule'
  tag stig_id: 'SRG-APP-000141-CTR-000320'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-35976r600704_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
