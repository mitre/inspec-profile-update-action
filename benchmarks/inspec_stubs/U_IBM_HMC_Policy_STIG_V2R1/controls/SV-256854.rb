control 'SV-256854' do
  title 'Power On Reset (POR) Procedures must be documented for each system.'
  desc 'If procedures for performing PORs are not in place, it is extremely difficult to ensure overall operating system integrity'
  desc 'check', 'Review the POR procedures with the System Administrator.
 Review documentation for completeness and accuracy.

	If no documentation exists, this is a FINDING'
  desc 'fix', 'Create or refine procedures for performing PORs.'
  impact 0.3
  ref 'DPMS Target IBM Hardware Management Console (HMC) Policies'
  tag check_id: 'C-60529r890906_chk'
  tag severity: 'low'
  tag gid: 'V-256854'
  tag rid: 'SV-256854r890908_rule'
  tag stig_id: 'HMCP0110'
  tag gtitle: 'SRG-OS-000360-GPOS-00147'
  tag fix_id: 'F-60472r890907_fix'
  tag 'documentable'
  tag legacy: ['V-24842', 'SV-30531']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
