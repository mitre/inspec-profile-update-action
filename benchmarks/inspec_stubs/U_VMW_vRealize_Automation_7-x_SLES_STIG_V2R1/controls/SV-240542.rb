control 'SV-240542' do
  title 'The SLES for vRealize must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The SLES for vRealize must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(Check the SSH daemon configuration for allowed MACs:

# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC other than "hmac-sha1", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs other than "hmac-sha1". If necessary, add a "MACs" line.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43775r671365_chk'
  tag severity: 'medium'
  tag gid: 'V-240542'
  tag rid: 'SV-240542r671398_rule'
  tag stig_id: 'VRAU-SL-001490'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-43734r671366_fix'
  tag 'documentable'
  tag legacy: ['SV-100511', 'V-89861']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
