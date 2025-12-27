control 'SV-239642' do
  title 'The SLES for vRealize must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The SLES for vRealize must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.'
  desc 'check', %q(Check the SSH daemon configuration for allowed MACs:

# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC other than "hmac-sha1", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs other than "hmac-sha1". If necessary, add a "MACs" line. 

# sed -i "/^[^#]*MACs/ c\\MACs hmac-sha1" /etc/ssh/sshd_config'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42875r662375_chk'
  tag severity: 'medium'
  tag gid: 'V-239642'
  tag rid: 'SV-239642r662408_rule'
  tag stig_id: 'VROM-SL-001465'
  tag gtitle: 'SRG-OS-000478-GPOS-00223'
  tag fix_id: 'F-42834r662376_fix'
  tag 'documentable'
  tag legacy: ['SV-99405', 'V-88755']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
