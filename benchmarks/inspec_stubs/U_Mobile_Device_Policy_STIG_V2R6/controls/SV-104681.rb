control 'SV-104681' do
  title 'Unclassified wireless devices must not be operated in Secure Spaces (as defined in DoDI 8420.01) unless required conditions are followed.'
  desc 'The operation of electronic equipment and emanations must be controlled in and around areas where sensitive information is kept or processed. Sites should post signs and train users to this requirement to mitigate this vulnerability.'
  desc 'check', 'Detailed Policy Requirements:

Note: This requirement does not apply to NSA-approved classified WLAN systems or SCIFs

The ISSO will ensure wireless devices are not operated in areas where classified information is electronically stored, processed, or transmitted unless:
- Approved by the Authorizing Official (AO) in consultation with the Certified TEMPEST Technical Authority (CTTA).
- The wireless equipment is separated from the classified data equipment at the minimum distance determined by the CTTA and appropriate countermeasures, as determined by the CTTA, are implemented.

Check Procedures:

Review documentation. Work with the traditional security reviewer to verify the following:
1. If classified information is not processed at this site, mark as not a finding.
2. If the site has a written procedure prohibiting the use of wireless devices in areas where classified data processing occurs, mark as not a finding. Ask for documentation showing the CTTA was consulted about operation and placement of wireless devices. Acceptable proof would be the signature or initials of the CTTA on the architecture diagram or other evidence of coordination. IAW DoD policy, the CTTA must have a written separation policy for each classified area. 
3. Review written policies, training material, or user agreements to see if wireless usage in these areas is addressed. 
4. Verify proper procedures for wireless device use in classified areas is addressed in training program.

If wireless devices are used in or around classified processing areas but the CTTA has not designated a separation distance in writing, the AO has not coordinated with the CTTA, or 
users are not trained or made aware (using signage or user agreement) of procedures for wireless device usage in and around classified processing areas, this is a finding.'
  desc 'fix', 'Have the Certified TEMPEST Technical Authority (CTTA) designate a separation distance between wireless devices and classified data-processing equipment in writing.

AO must coordinate with the CTTA.

Train users or get a signed user agreement on procedures for wireless device usage in and around classified processing areas.'
  impact 0.5
  ref 'DPMS Target Mobile Device Policy'
  tag check_id: 'C-94047r1_chk'
  tag severity: 'medium'
  tag gid: 'V-94851'
  tag rid: 'SV-104681r1_rule'
  tag stig_id: 'WIR0040'
  tag gtitle: 'CTTA coordination for secure spaces'
  tag fix_id: 'F-100975r1_fix'
  tag 'documentable'
end
