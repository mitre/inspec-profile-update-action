control 'SV-21745' do
  title 'Critical network equipment must be redundant and in geographically diverse locations for a site supporting C2 users.'
  desc 'The enhanced reliability and availability achieved by the implementation of redundancy and geographic diversity throughout the DISN Core along with the implementation of dual homed circuits via geographically diverse pathways and facilities is negated if both access circuits enter the enclave via the same facility containing a single Customer Edge Router (CER) connected to a single Session Border Controller (SBC). The reliability, redundancy, and robustness of the CER, SBC, and power source are subverted when the facility represents a single point of failure. For a small number of C2 users this may be less concerning but with more C2 users supported by the system, the greater the issue. Even less severe eventualities may limit the capability of the system to support reliable communications. 

The mitigation for this system wide vulnerability is to implement redundant facilities to which the geographically diverse pathways containing the dual homed access circuits can run and terminate on redundant, geographically separated sets of CERs, SBCs, and core LAN equipment. Session controllers can also be separated in this manner. This mitigation is costly and facilities housing critical communications infrastructure are not lost very often. However, the cost of mitigating this vulnerability must be weighed against the loss of critical communications, particularly in time of crisis. If the site supports large numbers of high level C2 users or special-C2 users, the cost of losing communications may outweigh the cost of providing redundant facilities. Another consideration should be access to emergency services via the communications system would also be lost. 

The threat to strategic facilities is greater from natural causes than from damage due to acts of war or terrorism. However, all threats must be considered. Tactical facilities have a higher vulnerability to acts of war, on a par with or exceeding the vulnerability posed by natural events.'
  desc 'check', 'Review site documentation to confirm critical network equipment is redundant and in geographically diverse locations for a site supporting C2 users. Redundant sets of CERs, SBCs, and session controllers must be housed in geographically diverse facilities within the site such that if one of locations is lost or isolated from the network, communications service is maintained. Sites facilities with a Soft Switch should have a session controller implemented in a geographically diverse location. If critical network equipment does not have redundant equipment, this is a finding. If redundant critical network equipment is not in a geographically diverse location, this is a finding.

If it is determined, following a cost versus benefit study and risk analysis, that redundant facilities containing dual sets of CERs, SBCs, and session controllers are not warranted for the given site, this requirement should be marked as a finding with a justification included in the POA&M stating the Authorizing Official (AO) is cognizant of and accepts the risk.

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  desc 'fix', 'Implement and document critical network equipment as redundant and in geographically diverse locations for a site supporting C2 users. Critical network equipment includes CERs, SBCs, and session controllers (or Soft Switches in combination with session controllers).

NOTE: The VVoIP system may allow SIP and SRTP traffic encrypted and encapsulated on port 443 from Cloud Service Providers.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23886r3_chk'
  tag severity: 'low'
  tag gid: 'V-19604'
  tag rid: 'SV-21745r3_rule'
  tag stig_id: 'VVoIP 6150'
  tag gtitle: 'VVoIP 6150'
  tag fix_id: 'F-20303r4_fix'
  tag 'documentable'
end
