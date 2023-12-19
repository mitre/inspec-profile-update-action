control 'SV-206856' do
  title 'The Voice Video Session Manager must provide Fire and Emergency Services (FES) with the Automatic Number Identification (ANI) of the initiator of the call.'
  desc "Configuring the voice video session manager to implement enhanced 911 (E911) and FES ensures compliance with Federal Communications Commission rules and establishes a common security baseline across DoD Voice Video systems. If E911 services are incorrectly configured, first responders may not have sufficient information to provide emergency services. Additionally, an adversary may use incorrectly configured E911 services to attack a system or location. For DoD systems, it is essential for FES communications to have sufficient priority, providing number and location information that is accurate.

The FCC requires that providers of interconnected VoIP telephone services meet E911 obligations. E911 systems automatically provide to emergency service personnel a 911 caller's call back number and, in most cases, location information. Next Generation 9-1-1 (NG911) is an initiative updating the current E911 service infrastructure in the United States and Canada to improve public emergency communications services in a growingly wireless mobile society. This new service would enable the public to transmit text, images, video and data to the PSAP."
  desc 'check', 'Verify the Voice Video Session Manager provides FES with the ANI of the initiator of the call.

If the Voice Video Session Manager does not provide FES with the ANI of the initiator of the call, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to provide FES with the ANI of the initiator of the call.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7111r364757_chk'
  tag severity: 'medium'
  tag gid: 'V-206856'
  tag rid: 'SV-206856r508661_rule'
  tag stig_id: 'SRG-NET-000512-VVSM-00043'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-7111r364758_fix'
  tag 'documentable'
  tag legacy: ['SV-76633', 'V-62143']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
