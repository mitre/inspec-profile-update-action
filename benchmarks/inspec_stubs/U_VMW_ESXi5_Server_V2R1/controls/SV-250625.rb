control 'SV-250625' do
  title 'The system must verify the integrity of the installation media before installing ESXi.'
  desc 'Any changes to the hardware, software, and/or firmware components of the information system and/or application can potentially have significant effects on the overall security of the system. 

Accordingly, software defined by the organization as critical software must be signed with a certificate that is recognized and approved by the organization.'
  desc 'check', "The downloaded ISO, offline bundle, or patch hash must be verified against the vendor's checksum to ensure the integrity and authenticity of the files. 
See some typical command line example(s) for both the md5 and sha1 hash check(s) directly below.
# md5sum <filename>.iso
# sha1sum <filename>.iso

If any of the system's downloaded ISO, offline bundle, or system patch hashes cannot be verified against the vendor's checksum, this is a finding."
  desc 'fix', "If the hash returned from the md5sum or sha1sum commands do not match the vendor's hash, the downloaded software must be discarded. 

If the physical media is obtained from VMware and the security seal is broken, the software must be returned to VMware for replacement."
  impact 0.7
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54060r798872_chk'
  tag severity: 'high'
  tag gid: 'V-250625'
  tag rid: 'SV-250625r798874_rule'
  tag stig_id: 'SRG-OS-000090-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54014r798873_fix'
  tag 'documentable'
  tag legacy: ['V-39387', 'SV-51245']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
