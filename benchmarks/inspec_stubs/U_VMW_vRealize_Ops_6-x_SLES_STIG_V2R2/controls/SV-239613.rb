control 'SV-239613' do
  title 'The SLES for vRealize must implement cryptographic mechanisms to prevent unauthorized disclosure of information and/or detect changes to information during transmission unless otherwise protected by alternative physical safeguards, such as, at a minimum, a Protected Distribution System (PDS).'
  desc 'Encrypting information for transmission protects information from unauthorized disclosure and modification. Cryptographic mechanisms implemented to protect information integrity include, for example, cryptographic hash functions that have common application in digital signatures, checksums, and message authentication codes. 

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to leverage transmission protection mechanisms such as TLS, SSL VPNs, or IPsec.

Alternative physical protection measures include PDS. PDSs are used to transmit unencrypted classified National Security Information (NSI) through an area of lesser classification or control. Since the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation.'
  desc 'check', %q(Check the SSH daemon configuration for allowed MACs:

# grep -i macs /etc/ssh/sshd_config | grep -v '^#' 

If no lines are returned, or the returned MACs list contains any MAC other than "hmac-sha1", this is a finding.)
  desc 'fix', 'Edit the SSH daemon configuration and remove any MACs other than "hmac-sha1". If necessary, add a "MACs" line. 

# sed -i "/^[^#]*MACs/ c\\MACs hmac-sha1" /etc/ssh/sshd_config'
  impact 0.7
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42846r662288_chk'
  tag severity: 'high'
  tag gid: 'V-239613'
  tag rid: 'SV-239613r878122_rule'
  tag stig_id: 'VROM-SL-001290'
  tag gtitle: 'SRG-OS-000424-GPOS-00188'
  tag fix_id: 'F-42805r662289_fix'
  tag 'documentable'
  tag legacy: ['SV-99347', 'V-88697']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
