control 'SRG-NET-000512-VVEP-00103_rule' do
  title 'The Unified Communications Endpoint must be configured to disable any auto answer features.'
  desc 'A Unified Communications Endpoint set to automatically answer a call with audio or video capabilities enabled risks transmitting information not intended for the caller. In the event a Unified Communications Endpoint automatically answered a call during a classified meeting or discussion, potentially sensitive or classified information could be transmitted. The auto-answer feature must not be activated by a user unless the feature is required to satisfy mission requirements.'
  desc 'check', 'Verify the Unified Communications Endpoint is configured to disable any auto answer features. 

If the Unified Communications Endpoint is not configured to disable auto answer features, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to disable auto answer features.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000512-VVEP-00103_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000512-VVEP-00103'
  tag rid: 'SRG-NET-000512-VVEP-00103_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00103'
  tag gtitle: 'SRG-NET-000512-VVEP-00103'
  tag fix_id: 'F-SRG-NET-000512-VVEP-00103_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
