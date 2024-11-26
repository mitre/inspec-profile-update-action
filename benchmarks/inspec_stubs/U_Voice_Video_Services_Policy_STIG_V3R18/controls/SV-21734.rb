control 'SV-21734' do
  title 'Local commercial phone service must be provided in support of Continuity Of Operations (COOP) and Fire and Emergency Services (FES) communications.'
  desc 'Voice phone services are critical to the effective operation of the DoD mission. We rely on these services being available when they are needed. Additionally, it is critical that phone service is available in the event of an emergency situation such as a security breach or life safety event. The ability of maintaining the ability to place calls to emergency services must be maintained. While the DoD voice networks are designed to be extremely reliable, such that COOP is supported, there is the potential that a site will be cut off from the DoD network. Based on this fact, each physical site must maintain local commercial phone service in the event the site is cut off. While this works to maintain local emergency service availability for security and life safety emergencies, it also provides the capability to make calls between DoD sites using the commercial network. An additional, non-IA benefit is that this supports the ability to make local calls without having to pay toll charges to call a local number via some distant regional access point. Local phone service can be delivered in a number of ways, all of which meet this requirement, while some of them must meet additional requirements to secure them.

Delivery options are as follows:
- PRI or CAS TDM trunks
- Analog phone lines

The following are some examples:
- A large site may use PRI, CAS, or POTS analog trunks connected to the site’s PBX.
- A small site or office attached to a large site.
+ May have a PBX and be served similar to a large site.
+ May be served by several analog phone lines terminated on Voice Video Endpoints.'
  desc 'check', 'If the system does not support a minimum of 96 instruments, this is Not Applicable.

If the site is in a tactical war zone where “friendly” service is not available, this is Not Applicable.

Interview the ISSO to verify the site has local analog or TDM commercial phone service provided to support COOP and FES calls. The two most common methods to implement TDM or VVoIP systems are as follows:
- Connect local commercial service to the site’s local phone system/switch (TDM or VVoIP) and program access to the local service from all Voice Video Endpoints.
- Connect local commercial service to dedicated Voice Video Endpoints (separate from the site’s local phone system) throughout the facility and accessible in all work areas. These dedicated Voice Video Endpoints may be stand alone or part of a dedicated a key system, PBX, or VVoIP network separate from the site’s local VVoIP or TDM phone system.
- Sites may use mobile devices for COOP and FES calls in support of non-sensitive unclassified areas.
Note: The IA premise of this requirement is “availability” and COOP. The purpose of this requirement is to provide local commercial service in the event the site is cut off from DISN service or the main site to which the local site is subtended and tethered.

If the site does not have local analog or TDM commercial phone service provided to support COOP and FES calls, this is a finding.

If the local commercial service is VoIP or VVoIP, this is a finding.'
  desc 'fix', 'Implement local commercial phone service (analog or TDM) according to the size of the site and the following:

Ensure local analog or TDM commercial phone service supports COOP and FES calls. This applies to TDM or VVoIP systems conditionally as follows:
- Connect local commercial service to the site’s local phone system/switch (TDM or VVoIP) and program access to the local service from all Voice Video Endpoints.
- Connect local commercial service to dedicated Voice Video Endpoints (separate from the site’s local phone system) throughout the facility and accessible in all work areas. These dedicated Voice Video Endpoints may be stand alone or part of a dedicated a key system, PBX, or VVoIP network separate from the site’s local VVoIP or TDM phone system.
- Sites may use mobile devices for COOP and FES calls in support of non-sensitive unclassified areas.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23865r3_chk'
  tag severity: 'medium'
  tag gid: 'V-19593'
  tag rid: 'SV-21734r3_rule'
  tag stig_id: 'VVoIP 1225'
  tag gtitle: 'VVoIP 1225'
  tag fix_id: 'F-20291r3_fix'
  tag 'documentable'
end
