control 'SV-40039' do
  title 'The VPN client on wireless clients (PDAs, smartphones) used for remote access to DoD networks must be FIPS 140-2 validated.'
  desc 'DoD data could be compromised if transmitted data is not secured with a compliant VPN.  FIPS validation provides a level of assurance that the encryption of the device has been securely implemented.'
  desc 'check', 'Interview the IAO and/or site wireless device administrator and inspect a sample (3-4) of site devices. Review VPN client
specification sheets and FIPS 140-2 certificate. Verify the
devices have a VPN client installed and that it is FIPS 140-2
validated. Mark as a finding if the VPN is not FIPS 140-2
validated.'
  desc 'fix', 'Comply with requirement.'
  impact 0.5
  ref 'DPMS Target PDA/PED'
  tag check_id: 'C-39052r1_chk'
  tag severity: 'medium'
  tag gid: 'V-18627'
  tag rid: 'SV-40039r1_rule'
  tag stig_id: 'WIR-MOS-PDA-034-01'
  tag gtitle: 'Remote access VPN - FIPS 140-2'
  tag fix_id: 'F-20573r6_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
end
