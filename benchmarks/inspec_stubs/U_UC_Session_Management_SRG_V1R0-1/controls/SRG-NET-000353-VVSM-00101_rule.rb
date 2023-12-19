control 'SRG-NET-000353-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to provide an indication of current participants in all calls, meetings, and conferences.'
  desc 'Providing an explicit indication of current participants in videoconferences helps to prevent unauthorized individuals from participating in collaborative videoconference sessions without the explicit knowledge of other participants. videoconferences allow groups of users to collaborate and exchange information. Without knowing who is in attendance, information could be compromised. For videoconferences with large numbers of people present, the identified participant may be listed as the room rather than by each individual attending.

Unified Communications Session Managers that provide a videoconference capability must provide a clear indication of who is attending the meeting, thus providing all attendees with the capability to clearly identify users who are in attendance.'
  desc 'check', 'Verify the Unified Communications Session Manager provides an indication of current participants in all calls, meetings, and conferences.

If the Unified Communications Session Manager does not provide an indication of current participants in all calls, meetings and conferences, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to provide an indication of current participants in all calls, meetings, and conferences.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000353-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000353-VVSM-00101'
  tag rid: 'SRG-NET-000353-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000353-VVSM-00101'
  tag gtitle: 'SRG-NET-000353-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000353-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002453']
  tag nist: ['SC-15 (4)']
end
