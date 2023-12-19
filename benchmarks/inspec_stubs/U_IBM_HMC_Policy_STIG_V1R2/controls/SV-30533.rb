control 'SV-30533' do
  title 'Backup of critical data for the HMC and its components  must be documented and tracked'
  desc 'If procedures for performing backup and recovery of critical data for the HMC  is not in place, system recoverability may be jeopardized and overall security compromised.'
  desc 'check', 'Review the documentation for backup of critical data for a HMC with the System Administrator.
Review documentation for completeness and accuracy.

If no documentation exists, this is a FINDING.'
  desc 'fix', 'Verify that procedures for backup of the critical data for the HMCs are properly documented. If not, create Backup Procedures documentation.

CPC data should be backed-up when configuration or CPC- licensed internal code changes have been made or as a routine preventive maintenance procedure.'
  impact 0.5
  ref 'DPMS Target IBM HMC LIC Policy'
  tag check_id: 'C-30871r1_chk'
  tag severity: 'medium'
  tag gid: 'V-24844'
  tag rid: 'SV-30533r1_rule'
  tag stig_id: 'HMCP0130'
  tag gtitle: 'HMCP0130'
  tag fix_id: 'F-27491r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', 'Information Assurance Manager', 'Systems Programmer']
  tag ia_controls: 'COTR-1'
  tag cci: ['CCI-000537']
  tag nist: ['CP-9 (b)']
end
