control 'SV-256856' do
  title 'Backup of critical data for the HMC and its components  must be documented and tracked'
  desc 'If procedures for performing backup and recovery of critical data for the HMC  is not in place, system recoverability may be jeopardized and overall security compromised.'
  desc 'check', 'Review the documentation for backup of critical data for a HMC with the System Administrator.
Review documentation for completeness and accuracy.

If no documentation exists, this is a FINDING.'
  desc 'fix', 'Verify that procedures for backup of the critical data for the HMCs are properly documented. If not, create Backup Procedures documentation.

CPC data should be backed-up when configuration or CPC- licensed internal code changes have been made or as a routine preventive maintenance procedure.'
  impact 0.5
  ref 'DPMS Target IBM Hardware Management Console (HMC) Policies'
  tag check_id: 'C-60531r890912_chk'
  tag severity: 'medium'
  tag gid: 'V-256856'
  tag rid: 'SV-256856r890914_rule'
  tag stig_id: 'HMCP0130'
  tag gtitle: 'SRG-OS-000360-GPOS-00147'
  tag fix_id: 'F-60474r890913_fix'
  tag 'documentable'
  tag legacy: ['V-24844', 'SV-30533']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
