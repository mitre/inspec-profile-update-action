control 'SV-21733' do
  title 'The sites enclave boundary protection must route commercial VoIP traffic via a local Media Gateway (MG) connected to a commercial service provider using PRI, CAS, or POTS analog trunks.'
  desc 'There are several reasons why VVoIP system access to local voice services must use a locally implemented MG connected to commercial voice services, including: 
 - The implementation or receipt of commercial VoIP service provides a path to the Internet. These “back doors” into the local network place the DISN at risk from exploitation Such connections need to be specifically approved under CJCSI 6211.02C and DODI 4640.14. Such connections must also meet the requirements in the Network Infrastructure STIG for an “Approved Gateway.” This generally means that a full boundary architecture has to be implemented. 
 - A PRI or CAS trunk is required because the DSN is not permitted to exchange SS7 signaling with the PSTN. Doing so would place the DoD’s SS7 network at risk. 
 - Local access is necessary to support Fire and Emergency Services (FES) calls.'
  desc 'check', 'If the site is small and has POTS lines terminated on individual phones, a dedicated key system, or a PBX, all of which are separate from the DoD VVoIP system, this is Not Applicable.

If the site is subtended to an enclave with approved IP voice services providing commercial service, this is Not Applicable.

Verify all VVoIP system access to/from commercial dialup services (voice, video, fax, data) is via a local MG using a PRI, CAS, or POTS analog trunk to a commercial service provider.

If the site is not connected to the PSTN via a MG located within the local site enclave as described above, this is a finding. 

NOTE: Trunks that support SS7 signaling and SS7 based signaling between a DoD network and a non-DOD network is prohibited.'
  desc 'fix', 'Ensure all VVoIP system access to/from commercial dialup services (voice, video, fax, data) is via a locally implemented MG using a PRI, CAS, or POTS analog trunk to a commercial service provider.

NOTE: Trunks that support SS7 signaling and SS7 based signaling between a DoD network and a non DOD network is prohibited.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23864r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19592'
  tag rid: 'SV-21733r2_rule'
  tag stig_id: 'VVoIP 1015'
  tag gtitle: 'VVoIP 1015'
  tag fix_id: 'F-20290r2_fix'
  tag 'documentable'
end
