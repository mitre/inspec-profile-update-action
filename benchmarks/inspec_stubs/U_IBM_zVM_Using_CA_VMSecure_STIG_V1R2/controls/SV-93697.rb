control 'SV-93697' do
  title 'IBM z/VM must employ Clock synchronization software.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Determine if Clock synchronization software is use.

If there is no Clock synchronization software in use, this is a finding.

Determine if configuration allows for the synchronizing internal Clock to authoritative source.

If software is improperly configured, this is a finding.'
  desc 'fix', 'Configure Clock synchronizing software to compare internal clock to authoritative source at least every 24 hours and when time difference is greater than one second.'
  impact 0.5
  ref 'DPMS Target z/VM Using CA VM:Secure'
  tag check_id: 'C-78579r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78991'
  tag rid: 'SV-93697r1_rule'
  tag stig_id: 'IBMZ-VM-002420'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-85741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
