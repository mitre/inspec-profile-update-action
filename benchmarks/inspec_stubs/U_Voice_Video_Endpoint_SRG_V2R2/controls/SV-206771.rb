control 'SV-206771' do
  title 'The Voice Video Endpoint processing classified calls must  display the classification level and Security Access Level (SAL) for the call or conference in progress.'
  desc 'Without the association of security attributes to information, there is no basis for the network element to make security related access-control and flow-control decisions. Security attributes includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in process. If the security attributes are lost when the data is being processed, there is the risk of a data compromise.

Voice video endpoints processing classified calls must display the appropriate security classification and SAL to ensure users protect information accordingly. Further, endpoints must be compatible with STU-III and STE displays. Voice video endpoints must indicate:
 - SCI when the connected terminals are authorized to process SCI information
 - Foreign national presence when non-U.S. personnel are authorized uncontrolled access
 - Terminal identifier associated with distant STU-IIIs or STEs and RED switch subscriber terminals
 - Non-secure calls and conferences established through an unclassified switch or key system.

Note: Each DRSN RED telephone (except for the IST) must have, at a minimum, a two-line alphanumeric display with a minimum of 16-characters per line. The Integrated Services Telephone (IST) has a one-line, 40-character display instead of the two-line by 16-character display. These displays will show the following:
 - The first line will display the self-authenticating security level of the call or conference in progress.
 - The second line will display the identity data of the distant terminal or identify the network and/or equipment type associated with the distant party and when a conference call is in progress.
(Formerly DRSN 2384/2385)'
  desc 'check', 'If the Voice Video Endpoint does not process classified calls, this is Not Applicable.

Verify the Voice Video Endpoint processing classified calls displays the classification level and SAL for the call or conference in progress. 

If the Voice Video Endpoint processing classified calls does not display the classification level and SAL for the call or conference in progress, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to display the classification level and SAL for the call or conference in progress.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7027r363836_chk'
  tag severity: 'medium'
  tag gid: 'V-206771'
  tag rid: 'SV-206771r604140_rule'
  tag stig_id: 'SRG-NET-000311-VVEP-00063'
  tag gtitle: 'SRG-NET-000311'
  tag fix_id: 'F-7027r363837_fix'
  tag 'documentable'
  tag legacy: ['SV-91979', 'V-77283']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
