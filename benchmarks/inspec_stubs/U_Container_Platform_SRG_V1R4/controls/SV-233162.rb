control 'SV-233162' do
  title 'The container platform must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.'
  desc 'Controlling what users can perform privileged functions prevents unauthorized users from performing tasks that may expose data or degrade the container platform. When users are not segregated into privileged and non-privileged users, unauthorized individuals may perform tasks such as deploying containers, pulling images into the register, and modify keys in the keystore. These actions can introduce malicious containers and cause denial-of-service (DoS) attacks and undermine the container platform integrity. The enforcement may take place at the container platform and can be implemented within each container platform component (e.g. runtime, registry, and keystore).'
  desc 'check', 'Review documentation to obtain the definition of the container platform functionality considered privileged in the context of the information system in question. 

Review the container platform security configuration and/or other means used to protect privileged functionality from unauthorized use. 

If the configuration does not protect all of the actions defined as privileged, this is a finding.'
  desc 'fix', 'Configure the container platform to security to protect all privileged functionality. Assigning roles that limit what actions a particular user can perform are the most common means of meeting this requirement.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36098r601762_chk'
  tag severity: 'medium'
  tag gid: 'V-233162'
  tag rid: 'SV-233162r879717_rule'
  tag stig_id: 'SRG-APP-000340-CTR-000770'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-36066r600974_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
