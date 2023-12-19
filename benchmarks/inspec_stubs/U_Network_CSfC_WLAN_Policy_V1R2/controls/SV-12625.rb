control 'SV-12625' do
  title 'Wireless devices must not be allowed in a permanent, temporary, or mobile Sensitive Compartmented Information Facilities (SCIFs), unless approved by the SCIF Cognizant Security Authority (CSA) in accordance with Intelligence Community Directive 503 and Director Central Intelligence Directive (DCID) 6/9, the DAA, and the site Special Security Officer (SSO).'
  desc 'Emanations from computing devices in the secured area may be transmitted or picked up inadvertently by wireless devices.'
  desc 'check', 'For SME PED: This requirement is not applicable. 
Work with the traditional reviewer or interview the IAO or SM. 

Determine if the site SCIF CSA has approved wireless CMDs in the site SCIFs. Determine if the DAA and site SSO have approved wireless CMDs in site SCIFs. Ask for approval documentation, if approval has been granted. All three entities must grant approval (SCIF CSA, DAA, and SSO).
If wireless CMDs in site SCIFs have not been approved, determine if procedures are in place to prevent users from bringing CMDs into SCIFs and if users are trained on this requirement. Posted signs are considered evidence of compliance. 

If wireless devices have been approved for use in SCIFs:
- Determine if site has written procedures that describe what type of CMDs and under what type of conditions (i.e., turned off, SCIF mode enabled, etc.) approval is granted.
- Users must receive proper training on the handling of wireless devices in SCIFs. 

Mark this as a finding if: 
- Wireless devices are allowed in site SCIFs without required approvals.
- Required procedures are not in place. 
- Required user training has not been documented.'
  desc 'fix', 'Ensure users are trained on the need to comply with this requirement and/or site procedures document the policy.  Alternately, this requirement can be included in the site User Agreement.'
  impact 0.7
  ref 'DPMS Target CSfC Policy - WLAN CP'
  tag check_id: 'C-8089r4_chk'
  tag severity: 'high'
  tag gid: 'V-12072'
  tag rid: 'SV-12625r5_rule'
  tag stig_id: 'WIR0035'
  tag gtitle: 'Wireless devices in SCIFs are DCID/ICD compliant'
  tag fix_id: 'F-11360r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager', 'Other']
  tag ia_controls: 'ECSC-1, ECWN-1'
end
