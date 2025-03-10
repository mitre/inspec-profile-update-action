control 'SV-21818' do
  title 'The MFSS is NOT configured to synchronize minimally with a paired MFSS and/or others such that each may serve as a backup for the other when signaling with its assigned LSCs, thus reducing the reliability and survivability of the DISN IPVS network.'
  desc 'MFSSs are critical to the operation of the DISN NIPRNet IPVS network. They broker the establishment of calls between enclaves. A MFSS provides the following functions: 
> Receives AS-SIP-TLS messages from other MFSSs and a specific set of regionally associated LSCs to act as a call routing manager across the backbone. 
> Sends AS-SIP-TLS messages to interrogate the ability of another MFSS or a LSC to receive a call, whether routine or priority. 
> Sends AS-SIP-TLS messages to manage the establishment of priority calls and the pre-emption of lower priority calls to LSCs and other MFSSs 
> Once a “trunk side” session request is received the MFSS determines if the destination is one of its assigned LSC’s. If so, it interrogates that LSC to determine if it can receive the call. If so, it signals to establish the call. If the destination is not one of its LSCs it signals with other MFSSs to locate the destination LSC and then the remote MFSS negotiates with its LSC. 
> Acts as a backup MFSS for LSCs assigned to other MFSSs as primary. As such, a LSC must be able to signal with a MFSS in order to establish any call across the DISN WAN. LSCs do not interact directly with LSCs. This hierarchical arrangement is required in order to be able to manage and establish priority calls and manage access circuit budgets. We established previously that each LSC must have a backup MFSS. In support of this function MFSSs must be operated in pairs with all the information about its assigned LSCs replicated across the pair.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

Ensure the MFSS is configured to synchronize minimally with a paired MFSS  and/or others such that each may serve as a backup for the other when signaling with its assigned LSCs and regarding the overall operation of the DISN IPVS network and the negotiation of call establishment between enclaves.

NOTE: We have already established that the local LSC portion of the MFSS requires a local backup LSC such that the ability to establish calls within the enclave and to local commercial network and emergency services is maintained. This requirement does not address redundancy or COOP within the enclave.

Determine which other MFSS(s) is acting as backup for the MFSS under review. Additionally determine which LSCs are assigned this MFSS as primary and which LSCs are assigned this MFSS as backup.'
  desc 'fix', 'Ensure each MFSS is configured to synchronize with a paired MFSS such that each may serve as a backup for the other when signaling with its assigned LSCs and regarding the overall operation of the DISN IPVS network and the negotiation of call establishment between enclaves.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-24062r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19677'
  tag rid: 'SV-21818r2_rule'
  tag stig_id: 'VVoIP 6405'
  tag gtitle: 'Deficient MFSS config: MFSS Redundancy / COOP'
  tag fix_id: 'F-20383r1_fix'
  tag 'documentable'
end
