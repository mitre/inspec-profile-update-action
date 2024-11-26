control 'SV-8824' do
  title 'The sites enclave boundary protection must route DSN voice traffic via a local Media Gateway (MG) connected to a DSN service provider using the appropriate type of trunk based on the sites need to support C2 communications.'
  desc 'There are several reasons why DSN voice traffic must use a locally implemented MG connected to a DSN service provider using the appropriate type of trunk based on the site’s need to support C2 communications, including:
 - VVoIP has the potential to significantly degrade the standard data enclave boundary protection when the data enclave firewall handles VVoIP traffic, unless specifically designed to. VVoIP must not traverse a standard data firewall except under certain circumstances. 
 - For confidentiality, use of a MG eliminates the need for encryption on an IP WAN by placing the voice traffic on a traditional TDM network where the communications are more secure. Physical access to the wire or TDM switch is required to compromise TDM communication.
 - For availability and C2 support, VVoIP systems from different vendors may not be interoperable via IP. DoD’s efforts to develop interoperable standards with vendor assistance has reduced this risk. 
 - The use of a MG converts each vendor’s implementation to a common interoperable system, the TDM DSN.'
  desc 'check', 'If the site is approved for Sensitive But Unclassified (SBU) Voice, providing IP VoIP service including DSN connectivity, this is Not Applicable.

If the site is subtended to an enclave with approved IP voice services providing DSN services, this is Not Applicable.

Verify the site’s VVoIP system connects to a DSN service provider via a local MG. Ensure T619A trunks are used for C2 enclaves to provide MLPP support, or PRI, CAS, and POTS analog trunks are used for all other configurations to the DSN service provider.

If the site connects to a DSN service provider using T619A, PRI, CAS, or POTS analog trunks without using a local MG, this is a finding.

NOTE: This requirement dictates that each site’s VoIP enclave has a local (on site) MG for connecting the site locally to a DSN EO or MFS. The DSN EO or MFS may be located at a remote site, in which case the TDM trunks will carry the voice traffic between the sites. This arrangement means that VoIP traffic does not have to traverse the enclave boundary with the WAN, which is one of the reasons for the requirement.'
  desc 'fix', 'Configure the site’s VVoIP system to connect to a DSN service provider via a local MG. For C2 enclaves with any MLPP support needed, T619A trunks must be installed. For sites without an MLPP requirement, PRI, CAS, and POTS analog trunks should be used. The connections from the local MG to a DSN service provider via T619A, PRI, CAS, or POTS analog trunks.
 
NOTE: This does not apply to approved remote VoIP instruments or Soft Phones that connect to the VVoIP system enclave via an encrypted VPN and are therefore part of the enclave’s LAN.

NOTE: TDM or optical circuits should be bulk encrypted if using a commercial provider to supply any portion of the complete circuit. This will most likely be the case for the “last mile” connection to a DISN SDN since DoD owned facilities do not touch most sites. 

NOTE: organizational Intranets using encrypted site-to-site or meshed VPN tunnels across a DISN IP routed network must block local access to/from the DISN IP routed network (e.g., NIPRNet) at the VPN termination points unless a full boundary protection suite of equipment is implemented locally.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23861r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8329'
  tag rid: 'SV-8824r2_rule'
  tag stig_id: 'VVoIP 1010'
  tag gtitle: 'VVoIP 1010'
  tag fix_id: 'F-20287r3_fix'
  tag 'documentable'
end
