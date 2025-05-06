control 'SV-239524' do
  title 'The SLES for vRealize must not use UDP for NIS/NIS+.'
  desc 'Implementing NIS or NIS+ under UDP may make SLES for vRealize more susceptible to a denial of service attack and does not provide the same quality of service as TCP.'
  desc 'check', 'If SLES for vRealize does not use NIS or NIS+, this is not applicable.

Check if NIS or NIS+ is implemented using UDP:

# rpcinfo -p | grep yp | grep udp

If NIS or NIS+ is implemented using UDP, this is a finding.'
  desc 'fix', 'Configure SLES for vRealize to not use UDP for NIS and NIS+. Consult vendor documentation for the required procedure.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42757r662021_chk'
  tag severity: 'medium'
  tag gid: 'V-239524'
  tag rid: 'SV-239524r662023_rule'
  tag stig_id: 'VROM-SL-000525'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-42716r662022_fix'
  tag 'documentable'
  tag legacy: ['SV-99169', 'V-88519']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
