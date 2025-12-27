control 'SV-51527' do
  title 'The test and development environment must not have access to DoD operational networks.'
  desc 'Systems or devices used for test data that do not meet minimum IA standards for accreditation are a risk to a DoD operational network if allowed to communicate between environments.  Data that has not been fully tested and finalized for use in an operational network may cause unintended consequences, such as data loss or corruption.  Unvetted data allowed into a DoD operational network from non-IA-compliant machines may also contain malicious code that could be used to steal or damage live data.'
  desc 'check', 'Determine whether there are procedures in place to prohibit non-IA-compliant systems or devices from accessing any DoD operational network.  If no procedure is in place to prohibit connection to any DoD operational network by non-IA-compliant systems, this is a finding.'
  desc 'fix', 'Prohibit non-IA-compliant systems or devices in the test and development environment from accessing any DoD operational network or live data.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone D'
  tag check_id: 'C-46815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39660'
  tag rid: 'SV-51527r1_rule'
  tag stig_id: 'ENTD0210'
  tag gtitle: 'ENTD0210 - Test and development environment has access to DoD operational networks.'
  tag fix_id: 'F-44668r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
