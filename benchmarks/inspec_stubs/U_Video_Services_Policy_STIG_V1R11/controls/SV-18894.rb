control 'SV-18894' do
  title 'Access control measures must be implemented for all conferences hosted on a centralized MCU appliance.'
  desc 'nregulated access to conference scheduling by any individual who is not authorized can lead to the inadvertent disclosure of sensitive or classified information to individuals that may not have an appropriate need-to-know or proper security clearance or may lead to a denial-of-service for MCU facilities. Scheduling systems accessed by users or administrators via a web interface must comply with all of the requirements for a web server or applications server to include DoD PKI access control and auditing requirements for such devices and systems. Scheduling systems accessed via a collaboration tool must minimally utilize the access control required for accessing the collaboration application. Since an authorized user of a collaboration tool may or may not have the right to schedule VTC conferences, the scheduling application should receive user credentials from the collaboration application to determine authorization or the right must be controlled by the collaboration application. Scheduling systems accessed by administrators using other methods must also employ access control and auditing meeting DoD requirements.'
  desc 'check', 'Review site documentation to confirm access control measures are implemented to control access to conference scheduling systems such that only authorized individuals can schedule conferences. Verify that only authorized individuals are permitted to schedule conferences. Inspect VTC scheduling system to verify that only users that are identified for accessing and setting up scheduled VTC conferences have access to said scheduling function. If access control measures are not implemented for all conferences hosted on a centralized MCU appliance, this is a finding.'
  desc 'fix', 'Implement access control measures to control access to conference scheduling systems such that only authorized individuals can schedule conferences.'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-18990r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17720'
  tag rid: 'SV-18894r2_rule'
  tag stig_id: 'RTS-VTC 5120.00'
  tag gtitle: 'RTS-VTC 5120'
  tag fix_id: 'F-17617r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
