control 'SRG-NET-000338-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to require Voice Video Endpoints to re-register at least every three hours.'
  desc 'Device registration is a solution enabling an organization to manage devices. It is an additional layer of authentication ensuring only specific preauthorized devices can access the system. Registration is the process of authorizing endpoints to communicate with the session manager. Registration occurs with the SIP server in VoIP systems and with a gatekeeper in H.323 systems. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Unified Communications Session Manager requires Voice Video Endpoints to re-register at least every three hours.

If the Unified Communications Session Manager does not require Voice Video Endpoints to re-register or does not enforce re-registration at least every three hours, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to re-register Voice Video Endpoints at least every three hours.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000338-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000338-VVSM-00101'
  tag rid: 'SRG-NET-000338-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000338-VVSM-00101'
  tag gtitle: 'SRG-NET-000338-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000338-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002039']
  tag nist: ['IA-11']
end
