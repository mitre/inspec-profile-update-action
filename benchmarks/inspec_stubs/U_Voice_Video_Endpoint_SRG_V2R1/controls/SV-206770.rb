control 'SV-206770' do
  title 'The Voice Video Endpoint processing classified calls must be properly marked with the highest security level of the information being processed.'
  desc 'Without the association of security attributes to information, there is no basis for the network element to make security related access-control and flow-control decisions. Security attributes includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in process. If the security attributes are lost when the data is being processed, there is the risk of a data compromise.

All hardware Voice Video endpoints processing classified calls, including phones and terminals, must be properly marked with the highest class-mark of the system. (Formerly DRSN 1098).'
  desc 'check', 'If the Voice Video Endpoint is a soft client, this is Not Applicable. 

If the Voice Video Endpoint does not process classified calls, this is Not Applicable.

Verify the Voice Video Endpoint processing classified calls is properly marked with the highest security level of the information being processed. 

If the Voice Video Endpoint processing classified calls is not properly marked with the highest security level of the information being processed, this is a finding.'
  desc 'fix', 'Properly mark the Voice Video Endpoint processing classified calls with the highest security level of the information being processed.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7026r363833_chk'
  tag severity: 'medium'
  tag gid: 'V-206770'
  tag rid: 'SV-206770r604140_rule'
  tag stig_id: 'SRG-NET-000311-VVEP-00062'
  tag gtitle: 'SRG-NET-000311'
  tag fix_id: 'F-7026r363834_fix'
  tag 'documentable'
  tag legacy: ['SV-91977', 'V-77281']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
