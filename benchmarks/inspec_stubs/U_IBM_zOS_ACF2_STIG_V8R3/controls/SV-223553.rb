control 'SV-223553' do
  title 'IBM z/OS PARMLIB CLOCKxx must have the Accuracy PARM coded properly.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time, a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Refer to the CLOCKxx member of PARMLIB.

If the ACCURACY parm is not coded, this is a finding.

If the ACCURACY parm is coded to "1000", this is not a finding.'
  desc 'fix', 'Define the CLOCKxx statement to include the ACCURACY parm set to "1000".'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25226r500794_chk'
  tag severity: 'medium'
  tag gid: 'V-223553'
  tag rid: 'SV-223553r533198_rule'
  tag stig_id: 'ACF2-OS-000170'
  tag gtitle: 'SRG-OS-000356-GPOS-00144'
  tag fix_id: 'F-25214r500795_fix'
  tag 'documentable'
  tag legacy: ['V-97811', 'SV-106915']
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
