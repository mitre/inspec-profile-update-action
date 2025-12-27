control 'SV-48282' do
  title 'Mobile systems must encrypt all data per the DoD Data at Rest policy.'
  desc 'If data at rest is unencrypted, it is vulnerable to disclosure.  Even if the operating system enforces permissions on data access, an adversary can remove non-volatile memory and read it directly, thereby circumventing operating system controls.   Encrypting the data ensures that confidentiality is protected even when the operating system is not running.'
  desc 'check', 'Verify the system employs DoD-approved full disk encryption.  If full disk encryption is not implemented, this is a finding.'
  desc 'fix', 'Install an approved DoD encryption package and enable full disk encryption.'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44960r1_chk'
  tag severity: 'high'
  tag gid: 'V-36665'
  tag rid: 'SV-48282r2_rule'
  tag stig_id: 'WN08-00-000013'
  tag gtitle: 'WN08-00-000013'
  tag fix_id: 'F-41417r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCR-1, ECCR-2'
  tag cci: ['CCI-001199', 'CCI-002475', 'CCI-002476']
  tag nist: ['SC-28', 'SC-28 (1)', 'SC-28 (1)']
end
