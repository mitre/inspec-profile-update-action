control 'SV-224027' do
  title 'The IBM z/OS systems requiring data at rest protection must properly employ IBM DS8880 for full disk encryption for classified systems.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', "Determine if IBM's DS880 Disks are in use.

If IBM DS880 Disks are not in use for systems that require data at rest, this is a finding."
  desc 'fix', "Employ IBM's DS8880 hardware to ensure full disk encryption."
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25700r516480_chk'
  tag severity: 'medium'
  tag gid: 'V-224027'
  tag rid: 'SV-224027r561402_rule'
  tag stig_id: 'TSS0-OS-000310'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-25688r516481_fix'
  tag 'documentable'
  tag legacy: ['V-98763', 'SV-107867']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
