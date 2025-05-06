control 'SV-21817' do
  title 'The VVoIP system connects with a DISN IPVS (NPRNET or SIPRNet) but the LSC(s) is not configured to signal with a backup MFSS (or SS) in the event the primary cannot be reached.'
  desc 'Redundancy of equipment and associations is used in and IP network to increase the availability of a system. Multiple MFSSs in the DISN NIPRNet IPVS network and multiple SSs in the DISN SIPRNet IPVS network have been implemented in each theatre to provide network wide redundancy of their functions. They are intended to work in pairs such that one can provide its backbone services to multiple LSCs that are configured to use one as a primary and the other as a backup. This is necessary to the maintenance of backbone functionality in the event there is a circuit (network path) failure, a MFSS or SS failure, or one of the sites housing a MFSS or SS is lost or the MFSS or SS becomes unavailable.  Based on this, when establishing a call on the WAN, each LSC must be configured to signal with a backup MFSS or SS in the event it cannot reach its primary.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications to any level of C2 user (Special C2, C2, C2(R)), ensure each enclave containing one or more LSCs is assigned to, associated with, or serviced by two DISN IPVS core backbone systems as follows:
> For DISN NIPRNet IPVS, each enclave will be serviced minimally by one primary and one secondary (backup) MFSS. 
> For DISN SIPRNet IPVS, each enclave will be serviced minimally by one primary and one secondary Soft Switch (SS) at the SIPRNET tier 0 routers.

Determine to which backbone MFSSs or SSs the enclaves LSC(s) is assigned as primary and backup.'
  desc 'fix', 'In the event the VVoIP system connects to the DISN WAN for VVoIP transport between enclaves AND the system is intended to provide assured service communications to any level of C2 user (Special C2, C2, C2(R)), ensure each enclave containing one or more LSCs is assigned to, associated with, or serviced by two DISN IPVS core backbone systems as follows:
> For DISN NIPRNet IPVS, each enclave will be serviced minimally by one primary and one secondary (backup) MFSS. 
> For DISN SIPRNet IPVS, each enclave will be serviced minimally by one primary and one secondary Soft Switch (SS) at the SIPRNET tier 0 routers.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24060r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19676'
  tag rid: 'SV-21817r2_rule'
  tag stig_id: 'VVoIP 6400'
  tag gtitle: 'Deficient Imp’n: Backup backbone MFSS or SS'
  tag fix_id: 'F-20382r1_fix'
  tag 'documentable'
end
