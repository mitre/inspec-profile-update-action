control 'SV-206838' do
  title 'The Voice Video Session Manager must restrict Voice Video endpoint user access outside of operational hours.'
  desc 'Activity under unusual conditions can indicate hostile activity. For example, what is normal activity during operational hours can indicate hostile activity if it occurs during off hours. Depending on mission needs and conditions, usage restrictions based on conditions and circumstances may be critical to limit access to resources and data to comply with operational or mission access control requirements. Thus, the network element must be configured to enforce the specific conditions or circumstances under which application accounts can be used (e.g., by restricting usage to certain days of the week, time of day, or specific durations of time).

Limiting access to the voice/video network by work hours and work week mitigates the risk of unauthorized access to the system outside of duty hours, reducing misuse or abuse of the system and its resources. Areas requiring service during other times may be identified. However, it is essential that endpoints be allowed access to emergency services at all times.'
  desc 'check', 'Verify the Voice Video Session Manager provides the capability to restrict Voice Video endpoint user access outside of operational hours to allow only essential connection capability. Areas requiring extended service times may be identified as exceptions.

If the Voice Video Session Manager does not restrict Voice Video endpoint user access outside of operational hours allowing for exceptions, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to restrict Voice Video endpoint user access outside of operational hours to only essential connections.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7093r364703_chk'
  tag severity: 'medium'
  tag gid: 'V-206838'
  tag rid: 'SV-206838r508661_rule'
  tag stig_id: 'SRG-NET-000315-VVSM-00003'
  tag gtitle: 'SRG-NET-000315'
  tag fix_id: 'F-7093r364704_fix'
  tag 'documentable'
  tag legacy: ['SV-76599', 'V-62109']
  tag cci: ['CCI-000366', 'CCI-002145']
  tag nist: ['CM-6 b', 'AC-2 (11)']
end
