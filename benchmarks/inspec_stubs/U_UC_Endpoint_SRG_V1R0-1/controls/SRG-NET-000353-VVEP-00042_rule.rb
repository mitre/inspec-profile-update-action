control 'SRG-NET-000353-VVEP-00042_rule' do
  title 'The Unified Communications Endpoint must provide an explicit indication of current participants in all Videoconference (VC)-based and IP-based online meetings and conferences.'
  desc 'Providing an explicit indication of current participants in teleconferences helps to prevent unauthorized individuals from participating in collaborative teleconference sessions without the explicit knowledge of other participants. Teleconferences allow groups of users to collaborate and exchange information. Without knowing who is in attendance, information could be compromised. 

Network elements that provide a teleconference capability must provide a clear indication of who is attending the meeting, thus providing all attendees with the capability to clearly identify users who are in attendance.'
  desc 'check', 'Verify the Unified Communications Endpoint provides an explicit indication of current participants in all VC-based and IP-based online meetings and conferences. This excludes audio-only teleconferences using traditional telephony.

If the Unified Communications Endpoint does not provide an explicit indication of current participants in all VC-based and IP-based online meetings and conferences, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint provides an explicit indication of current participants in all VC-based and IP-based online meetings and conferences.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000353-VVEP-00042_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000353-VVEP-00042'
  tag rid: 'SRG-NET-000353-VVEP-00042_rule'
  tag stig_id: 'SRG-NET-000353-VVEP-00042'
  tag gtitle: 'SRG-NET-000353-VVEP-00042'
  tag fix_id: 'F-SRG-NET-000353-VVEP-00042_fix'
  tag 'documentable'
  tag cci: ['CCI-002453']
  tag nist: ['SC-15 (4)']
end
