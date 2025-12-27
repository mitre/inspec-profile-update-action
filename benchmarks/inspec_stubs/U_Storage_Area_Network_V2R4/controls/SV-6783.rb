control 'SV-6783' do
  title 'The SAN is not configured to use FIPS 140-1/2 validated encryption algorithm to protect management-to-fabric communications.'
  desc "The communication between the SAN management consol and the SAN fabric carries sensitive privileged configuration data.  This data's confidentiality will be protected with FIPS 140-1/2 validate algorithm for encryption.  Configuration data could be used to create a denial of service by disrupting the SAN fabric.
The storage administrator will configure the SAN to use FIPS 140-1/2 validated encryption algorithm to protect management-to-fabric communications."
  desc 'check', 'The reviewer will, with the assistance of the storage administrator, verify that the SAN is configured to use FIPS 140-1/2 validated encryption algorithm to protect management-to-fabric communications.'
  desc 'fix', 'Develop a plan to implement FIPS-140-1/2 validated encryption to protect management-to-fabric communications.  Obtain CM approval of the plan and execute the plan.'
  impact 0.3
  ref 'DPMS Target SANS Storage Device'
  ref 'DPMS Target SANS Switch'
  tag check_id: 'C-2555r1_chk'
  tag severity: 'low'
  tag gid: 'V-6639'
  tag rid: 'SV-6783r1_rule'
  tag stig_id: 'SAN04.016.00'
  tag gtitle: 'FIPS 140-1/2 for management to fabric.'
  tag fix_id: 'F-6240r1_fix'
  tag 'documentable'
  tag responsibility: 'Other'
end
