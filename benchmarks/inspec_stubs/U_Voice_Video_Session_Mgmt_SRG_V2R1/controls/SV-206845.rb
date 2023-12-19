control 'SV-206845' do
  title 'The Voice Video Session Manager must require Voice Video peers to re-register (re-authenticate) at least every hour.'
  desc 'Device registration is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific pre-authorized devices and trunks can access the system. Registration is the process of authorizing endpoints and trunks to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device or peer on the Voice Video network.'
  desc 'check', 'Verify the Voice Video Session Manager requires Voice Video peers to re-register (re-authenticate) at least every hour.

If the Voice Video Session Manager does not require Voice Video peers to re-register (re-authenticate) at least every hour, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to re-register (re-authenticate) Voice Video peers at least every hour.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7100r504894_chk'
  tag severity: 'medium'
  tag gid: 'V-206845'
  tag rid: 'SV-206845r508661_rule'
  tag stig_id: 'SRG-NET-000338-VVSM-00056'
  tag gtitle: 'SRG-NET-000338'
  tag fix_id: 'F-7100r504895_fix'
  tag 'documentable'
  tag legacy: ['V-71687', 'SV-86311']
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
