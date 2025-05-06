control 'SRG-NET-000015-VVEP-00102_rule' do
  title 'The Unified Communications Endpoint must be configured to register with a Unified Communications Session Manager.'
  desc 'For most VoIP systems, registration is the process of centrally recording the user ID, endpoint MAC address, service/policy profile with 2 stage authentication prior to authorizing the establishment of the session and user service. The event of successful registration creates the session record immediately. VC systems register using a similar process with a gatekeeper. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Unified Communications Endpoint registers with a Unified Communications Session Manager.

If the Unified Communications Endpoint does not register with a Unified Communications Session Manager, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to register with a Unified Communications Session Manager.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000015-VVEP-00102_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000015-VVEP-00102'
  tag rid: 'SRG-NET-000015-VVEP-00102_rule'
  tag stig_id: 'SRG-NET-000015-VVEP-00102'
  tag gtitle: 'SRG-NET-000015-VVEP-00102'
  tag fix_id: 'F-SRG-NET-000015-VVEP-00102_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
