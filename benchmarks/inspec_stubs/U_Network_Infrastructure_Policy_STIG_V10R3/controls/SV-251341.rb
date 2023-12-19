control 'SV-251341' do
  title 'Products collecting baselines for anomaly-based detection must have their baselines rebuilt based on changes to mission requirements such as Information Operations Conditions (INFOCON) levels and when the traffic patterns are expected to change significantly.'
  desc 'Administrators should ensure that any products collecting baselines for anomaly-based detection have their baselines rebuilt periodically as needed to support accurate detection. 

The ISSM is required to have the enclave prepared for readiness by raising INFOCON levels prior to an activity to ensure the network is as ready as possible when the operation or exercise begins. Because system and network administrators implement many of the INFOCON measures over a period of time in a pre-determined operational rhythm, commanders should raise INFOCON levels early enough to ensure completion of at least one cycle before the operational activity begins.  

Recommendations for possible INFOCON changes should be written into Operation Plans (OPLAN) and Concept Plans (CONPLAN). Guidelines can be found in Strategic Command Directive (SD) 527-1.'
  desc 'check', 'Interview the IDPS administrator and determine if anomaly-based detection is deployed in the network. If implemented, ensure that any products collecting baselines for anomaly-based detection have their baselines rebuilt periodically to support accurate detection.

If the collection products do not have their baselines rebuilt periodically, this is a finding.'
  desc 'fix', 'Establish procedures to update anomaly-based sensors.'
  impact 0.3
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-54776r805976_chk'
  tag severity: 'low'
  tag gid: 'V-251341'
  tag rid: 'SV-251341r805978_rule'
  tag stig_id: 'NET-IDPS-027'
  tag gtitle: 'NET-IDPS-027'
  tag fix_id: 'F-54729r805977_fix'
  tag 'documentable'
  tag legacy: ['V-18504', 'SV-20039']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
