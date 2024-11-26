control 'SV-207669' do
  title 'The ESXi host must verify the integrity of the installation media before installing ESXi.'
  desc 'Always check the SHA1 or MD5 hash after downloading an ISO, offline bundle, or patch to ensure integrity and authenticity of the downloaded files.'
  desc 'check', "The downloaded ISO, offline bundle, or patch hash must be verified against the vendor's checksum to ensure the integrity and authenticity of the files. 

See some typical command line example(s) for both the md5 and sha1 hash check(s) directly below.

# md5sum <filename>.iso
# sha1sum <filename>.iso

If any of the system's downloaded ISO, offline bundle, or system patch hashes cannot be verified against the vendor's checksum, this is a finding."
  desc 'fix', "If the hash returned from the md5sum or sha1sum commands do not match the vendor's hash, the downloaded software must be discarded. 

If the physical media is obtained from VMware and the security seal is broken, the software must be returned to VMware for replacement."
  impact 0.7
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7924r364406_chk'
  tag severity: 'high'
  tag gid: 'V-207669'
  tag rid: 'SV-207669r388482_rule'
  tag stig_id: 'ESXI-65-000071'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-7924r364407_fix'
  tag 'documentable'
  tag legacy: ['SV-104307', 'V-94477']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
