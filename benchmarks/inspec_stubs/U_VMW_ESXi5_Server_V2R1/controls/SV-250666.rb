control 'SV-250666' do
  title 'SAN resources must be masked and zoned appropriately.'
  desc 'SAN activity must be segregated via zoning and LUN masking. The potential for any SAN client to mount and access any SAN drive will result in disk resource contention and data corruption. Zoning and LUN masking must be used to isolate and protect SAN storage devices. Use of zoning must also take into account any host groups on the SAN device(s).'
  desc 'check', 'Zoning and masking capabilities for each SAN switch and disk array are vendor specific. Ask the SA if a SAN device is used to support hosts. If a SAN device is deployed and zoning/masking is not used, this is a finding.

If SAN devices are not used, this is not a finding.'
  desc 'fix', 'If SAN devices are used, a vendor-specific procedure must be developed and documented to mask/zone host LUNs.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54101r798995_chk'
  tag severity: 'low'
  tag gid: 'V-250666'
  tag rid: 'SV-250666r798997_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000150'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54055r798996_fix'
  tag 'documentable'
  tag legacy: ['SV-51120', 'V-39304']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
