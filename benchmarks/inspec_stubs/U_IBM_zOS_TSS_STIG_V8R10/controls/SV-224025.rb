control 'SV-224025' do
  title 'IBM z/OS PARMLIB CLOCKxx must have the Accuracy PARM coded properly.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems).

Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done in order to determine the time difference.'
  desc 'check', 'Refer to the CLOCKxx member of PARMLIB.

If the ACCURACY parm is not coded, this is a finding.

If the ACCURACY parm is coded to "1000", this is not a finding.'
  desc 'fix', 'Define the CLOCKxx statement to include the ACCURACY parm set to "1000".'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25698r516474_chk'
  tag severity: 'medium'
  tag gid: 'V-224025'
  tag rid: 'SV-224025r877865_rule'
  tag stig_id: 'TSS0-OS-000290'
  tag gtitle: 'SRG-OS-000356-GPOS-00144'
  tag fix_id: 'F-25686r516475_fix'
  tag 'documentable'
  tag legacy: ['V-98759', 'SV-107863']
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
