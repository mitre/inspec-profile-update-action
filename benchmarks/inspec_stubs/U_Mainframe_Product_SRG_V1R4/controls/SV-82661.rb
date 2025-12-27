control 'SV-82661' do
  title 'The Mainframe Product must prevent software as identified in the site security plan from executing at higher privilege levels than users executing the software.'
  desc 'In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by organizations.'
  desc 'check', 'Examine installation and configuration settings.

Determine that the Mainframe Product identifies functions requiring elevated privileges.

If the Mainframe Product uses an external security manager ensure that execution uses authority of the initiating user rather than that of the Mainframe Product. If it does not, this is a finding.

The Mainframe Product does not use an external security manager ensure installation and configuration settings use the authority of the initiating user rather than that of the Mainframe Product.

If it does not, this is a finding.'
  desc 'fix', 'Using information from the Mainframe Product about privileged function, configure the external security manager to enforce submitting jobs on behalf of another user parameters.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68733r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68171'
  tag rid: 'SV-82661r1_rule'
  tag stig_id: 'SRG-APP-000342-MFP-000090'
  tag gtitle: 'SRG-APP-000342-MFP-000090'
  tag fix_id: 'F-74287r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']
end
