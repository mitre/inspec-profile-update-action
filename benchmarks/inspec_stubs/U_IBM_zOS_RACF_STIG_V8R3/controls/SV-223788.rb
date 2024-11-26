control 'SV-223788' do
  title 'The IBM z/OS systems requiring data at rest protection must properly employ IBM DS8880 for full disk encryption for classified systems.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', "Determine if IBM's DS8880 Disks are in use.

If they are not in use for systems that require data at rest, this is a finding."
  desc 'fix', "Employ IBM's DS8880 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25461r571980_chk'
  tag severity: 'medium'
  tag gid: 'V-223788'
  tag rid: 'SV-223788r604139_rule'
  tag stig_id: 'RACF-OS-000320'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-25449r515053_fix'
  tag 'documentable'
  tag legacy: ['SV-107387', 'V-98283']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
