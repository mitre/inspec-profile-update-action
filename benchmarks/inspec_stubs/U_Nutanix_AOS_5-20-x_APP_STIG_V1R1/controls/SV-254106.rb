control 'SV-254106' do
  title 'Nutanix AOS must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'Determining the correct time a particular application event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronization of system clocks is needed in order to correctly correlate the timing of events that occur across multiple systems. To meet this requirement, the organization will define an authoritative time source and have each system compare its internal clock at least every 24 hours.

'
  desc 'check', 'Confirm Nutanix AOS Prism Elements is configured to use redundant NTP sources.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the NTP Servers section.
4. Ensure external NTP servers have been configured.

If external NTP sources are not configured, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS Prism Elements to use redundant authoritative NTP time sources.

1. Log in to Prism Element.
2. Click on the gear icon in the upper right.
3. Navigate to the NTP Servers section.
4. Configure two authoritative NTP servers.'
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x Application'
  tag check_id: 'C-57591r846404_chk'
  tag severity: 'low'
  tag gid: 'V-254106'
  tag rid: 'SV-254106r846406_rule'
  tag stig_id: 'NUTX-AP-000160'
  tag gtitle: 'SRG-APP-000371-AS-000077'
  tag fix_id: 'F-57542r846405_fix'
  tag satisfies: ['SRG-APP-000371-AS-000077', 'SRG-APP-000372-AS-000212', 'SRG-APP-000116-AS-000076']
  tag 'documentable'
  tag cci: ['CCI-000159', 'CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 a', 'AU-8 (1) (a)', 'AU-8 (1) (b)']
end
